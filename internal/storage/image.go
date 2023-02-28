package storage

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/containers/image/v5/copy"
	"github.com/containers/image/v5/signature"
	"github.com/containers/image/v5/types"
	encconfig "github.com/containers/ocicrypt/config"
	"github.com/containers/podman/v4/pkg/rootless"
	"github.com/containers/storage"
	"github.com/containers/storage/pkg/reexec"
	systemdDbus "github.com/coreos/go-systemd/v22/dbus"
	"github.com/cri-o/cri-o/internal/dbusmgr"
	"github.com/cri-o/cri-o/utils"
	"github.com/godbus/dbus/v5"
	json "github.com/json-iterator/go"
	digest "github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go/v1"
)

var (
	// ErrCannotParseImageID is returned when we try to ResolveNames for an image ID
	ErrCannotParseImageID = errors.New("cannot parse an image ID")
	// ErrImageMultiplyTagged is returned when we try to remove an image that still has multiple names
	ErrImageMultiplyTagged = errors.New("image still has multiple names applied")
)

// ImageResult wraps a subset of information about an image: its ID, its names,
// and the size, if known, or nil if it isn't.
type ImageResult struct {
	ID           string
	Name         string
	RepoTags     []string
	RepoDigests  []string
	Size         *uint64
	Digest       digest.Digest
	ConfigDigest digest.Digest
	User         string
	PreviousName string
	Labels       map[string]string
	OCIConfig    *specs.Image
	Annotations  map[string]string
}

type indexInfo struct {
	name   string
	secure bool
}

// ImageBeingPulled map[string]bool to keep track of the images haven't done pulling.
var ImageBeingPulled sync.Map

// CgroupPullConfiguration
type CgroupPullConfiguration struct {
	UseNewCgroup bool
	ParentCgroup string
}

// subset of copy.Options that is supported by reexec.
type ImageCopyOptions struct {
	SourceCtx        *types.SystemContext
	DestinationCtx   *types.SystemContext
	OciDecryptConfig *encconfig.DecryptConfig
	ProgressInterval time.Duration
	Progress         chan types.ProgressProperties `json:"-"`
	CgroupPull       CgroupPullConfiguration
}

// ImageServer wraps up various CRI-related activities into a reusable
// implementation.
type ImageServer interface {
	// ListImages returns list of all images which match the filter.
	ListImages(systemContext *types.SystemContext, filter string) ([]ImageResult, error)
	// ImageStatus returns status of an image which matches the filter.
	ImageStatus(systemContext *types.SystemContext, filter string) (*ImageResult, error)
	// PrepareImage returns an Image where the config digest can be grabbed
	// for further analysis. Call Close() on the resulting image.
	PrepareImage(systemContext *types.SystemContext, imageName string) (types.ImageCloser, error)
	// PullImage imports an image from the specified location.
	PullImage(systemContext *types.SystemContext, imageName string, options *ImageCopyOptions) (types.ImageReference, error)
	// UntagImage removes a name from the specified image, and if it was
	// the only name the image had, removes the image.
	UntagImage(systemContext *types.SystemContext, imageName string) error
	// GetStore returns the reference to the storage library Store which
	// the image server uses to hold images, and is the destination used
	// when it's asked to pull an image.
	GetStore() storage.Store
	// ResolveNames takes an image reference and if it's unqualified (w/o hostname),
	// it uses crio's default registries to qualify it.
	ResolveNames(systemContext *types.SystemContext, imageName string) ([]string, error)
}

// nolint: gochecknoinits
func init() {
	reexec.Register("crio-copy-image", copyImageChild)
}

type copyImageArgs struct {
	Lookup         *imageLookupService
	ImageName      string
	ParentCgroup   string
	SystemContext  *types.SystemContext
	Options        *ImageCopyOptions
	HasCollectMode bool

	StoreOptions storage.StoreOptions
}

// moveSelfToCgroup moves the current process to a new transient cgroup.
func moveSelfToCgroup(cgroup string, hasCollectMode bool) error {
	slice := "system.slice"
	if rootless.IsRootless() {
		slice = "user.slice"
	}

	if cgroup != "" {
		if !strings.Contains(cgroup, ".slice") {
			return fmt.Errorf("invalid systemd cgroup %q", cgroup)
		}
		slice = filepath.Base(cgroup)
	}

	unitName := fmt.Sprintf("crio-pull-image-%d.scope", os.Getpid())

	systemdProperties := []systemdDbus.Property{}
	if hasCollectMode {
		systemdProperties = append(systemdProperties,
			systemdDbus.Property{
				Name:  "CollectMode",
				Value: dbus.MakeVariant("inactive-or-failed"),
			})
	}

	return utils.RunUnderSystemdScope(dbusmgr.NewDbusConnManager(rootless.IsRootless()), os.Getpid(), slice, unitName, systemdProperties...)
}

func copyImageChild() {
	var args copyImageArgs

	if err := json.NewDecoder(os.NewFile(0, "stdin")).Decode(&args); err != nil {
		fmt.Fprintf(os.Stderr, "%v", err)
		os.Exit(1)
	}

	if err := moveSelfToCgroup(args.ParentCgroup, args.HasCollectMode); err != nil {
		fmt.Fprintf(os.Stderr, "%v", err)
		os.Exit(1)
	}

	store, err := storage.GetStore(args.StoreOptions)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v", err)
		os.Exit(1)
	}

	policy, err := signature.DefaultPolicy(args.SystemContext)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v", err)
		os.Exit(1)
	}
	policyContext, err := signature.NewPolicyContext(policy)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v", err)
		os.Exit(1)
	}

	srcSystemContext, srcRef, destRef, err := args.Lookup.getReferences(args.Options.SourceCtx, store, args.ImageName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v", err)
		os.Exit(1)
	}

	progress := make(chan types.ProgressProperties)
	go func() {
		stream := json.NewStream(json.ConfigDefault, os.Stdout, 4096)
		for p := range progress {
			stream.WriteVal(p)
			stream.WriteRaw("\n")
			if err := stream.Flush(); err != nil {
				fmt.Fprintf(os.Stderr, "%v", err)
				os.Exit(1)
			}
		}
	}()

	options := toCopyOptions(args.Options, progress)
	options.SourceCtx = srcSystemContext
	if _, err := copy.Image(context.Background(), policyContext, destRef, srcRef, options); err != nil {
		fmt.Fprintf(os.Stderr, "%v", err)
		os.Exit(1)
	}

	os.Exit(0)
}

func toCopyOptions(options *ImageCopyOptions, progress chan types.ProgressProperties) *copy.Options {
	return &copy.Options{
		SourceCtx:        options.SourceCtx,
		DestinationCtx:   options.DestinationCtx,
		OciDecryptConfig: options.OciDecryptConfig,
		ProgressInterval: options.ProgressInterval,
		Progress:         progress,
	}
}

// GetImageService returns an ImageServer that uses the passed-in store, and
// which will prepend the passed-in DefaultTransport value to an image name if
// a name that's passed to its PullImage() method can't be resolved to an image
// in the store and can't be resolved to a source on its own.
func GetImageService(ctx context.Context, sc *types.SystemContext, store storage.Store, defaultTransport string, insecureRegistries []string) (ImageServer, error) {
	if store == nil {
		var err error
		storeOpts, err := storage.DefaultStoreOptions(rootless.IsRootless(), rootless.GetRootlessUID())
		if err != nil {
			return nil, err
		}
		store, err = storage.GetStore(storeOpts)
		if err != nil {
			return nil, err
		}
	}
	ils := &imageLookupService{
		DefaultTransport:      defaultTransport,
		IndexConfigs:          make(map[string]*indexInfo),
		InsecureRegistryCIDRs: make([]*net.IPNet, 0),
	}
	is := &imageService_oci{
		lookup:     ils,
		store:      store,
		imageCache: make(map[string]imageCacheItem),
		ctx:        ctx,
	}

	insecureRegistries = append(insecureRegistries, "127.0.0.0/8")
	// Split --insecure-registry into CIDR and registry-specific settings.
	for _, r := range insecureRegistries {
		// Check if CIDR was passed to --insecure-registry
		_, ipnet, err := net.ParseCIDR(r)
		if err == nil {
			// Valid CIDR.
			is.lookup.InsecureRegistryCIDRs = append(is.lookup.InsecureRegistryCIDRs, ipnet)
		} else {
			// Assume `host:port` if not CIDR.
			is.lookup.IndexConfigs[r] = &indexInfo{
				name:   r,
				secure: false,
			}
		}
	}

	return is, nil
}

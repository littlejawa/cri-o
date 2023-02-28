package storage

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/containers/image/v5/copy"
	"github.com/containers/image/v5/docker/reference"
	"github.com/containers/image/v5/pkg/shortnames"
	"github.com/containers/image/v5/signature"
	istorage "github.com/containers/image/v5/storage"
	"github.com/containers/image/v5/transports/alltransports"
	"github.com/containers/image/v5/types"
	"github.com/containers/storage"
	"github.com/containers/storage/pkg/reexec"
	"github.com/cri-o/cri-o/internal/config/node"
	json "github.com/json-iterator/go"
	digest "github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/sirupsen/logrus"
)

const (
	minimumTruncatedIDLength = 3
)

// A set of information that we prefer to cache about images, so that we can
// avoid having to reread them every time we need to return information about
// images.
// Every field in imageCacheItem are fixed properties of an "image", which in this
// context is the image.ID stored in c/storage, and thus don't need to be recomputed.
type imageCacheItem struct {
	config       *specs.Image
	size         *uint64
	configDigest digest.Digest
	info         *types.ImageInspectInfo
	annotations  map[string]string
}

type imageCache map[string]imageCacheItem

type imageLookupService struct {
	DefaultTransport      string
	InsecureRegistryCIDRs []*net.IPNet
	IndexConfigs          map[string]*indexInfo
}

type imageService_oci struct {
	lookup         *imageLookupService
	store          storage.Store
	imageCache     imageCache
	imageCacheLock sync.Mutex
	ctx            context.Context
}

func (svc *imageService_oci) getRef(name string) (types.ImageReference, error) {
	ref, err := alltransports.ParseImageName(name)
	if err != nil {
		ref2, err2 := istorage.Transport.ParseStoreReference(svc.store, "@"+name)
		if err2 != nil {
			ref3, err3 := istorage.Transport.ParseStoreReference(svc.store, name)
			if err3 != nil {
				return nil, err
			}
			ref2 = ref3
		}
		ref = ref2
	}
	return ref, nil
}

func sortNamesByType(names []string) (bestName string, tags, digests []string) {
	for _, name := range names {
		if len(name) > 72 && name[len(name)-72:len(name)-64] == "@sha256:" {
			digests = append(digests, name)
		} else {
			tags = append(tags, name)
		}
	}
	if len(digests) > 0 {
		bestName = digests[0]
	}
	if len(tags) > 0 {
		bestName = tags[0]
	}
	return bestName, tags, digests
}

func (svc *imageService_oci) makeRepoDigests(knownRepoDigests, tags []string, img *storage.Image) (imageDigest digest.Digest, repoDigests []string) {
	// Look up the image's digests.
	imageDigest = img.Digest
	if imageDigest == "" {
		imgDigest, err := svc.store.ImageBigDataDigest(img.ID, storage.ImageDigestBigDataKey)
		if err != nil || imgDigest == "" {
			return "", knownRepoDigests
		}
		imageDigest = imgDigest
	}
	imageDigests := []digest.Digest{imageDigest}
	for _, anotherImageDigest := range img.Digests {
		if anotherImageDigest != imageDigest {
			imageDigests = append(imageDigests, anotherImageDigest)
		}
	}
	// We only want to supplement what's already explicitly in the list, so keep track of values
	// that we already know.
	digestMap := make(map[string]struct{})
	repoDigests = knownRepoDigests
	for _, repoDigest := range knownRepoDigests {
		digestMap[repoDigest] = struct{}{}
	}
	// For each tagged name, parse the name, and if we can extract a named reference, convert
	// it into a canonical reference using the digest and add it to the list.
	for _, name := range append(tags, knownRepoDigests...) {
		if ref, err2 := reference.ParseNormalizedNamed(name); err2 == nil {
			trimmed := reference.TrimNamed(ref)
			for _, imageDigest := range imageDigests {
				if imageRef, err3 := reference.WithDigest(trimmed, imageDigest); err3 == nil {
					if _, ok := digestMap[imageRef.String()]; !ok {
						repoDigests = append(repoDigests, imageRef.String())
						digestMap[imageRef.String()] = struct{}{}
					}
				}
			}
		}
	}
	return imageDigest, repoDigests
}

func (svc *imageService_oci) buildImageCacheItem(systemContext *types.SystemContext, ref types.ImageReference) (imageCacheItem, error) {
	imageFull, err := ref.NewImage(svc.ctx, systemContext)
	if err != nil {
		return imageCacheItem{}, err
	}
	defer imageFull.Close()
	configDigest := imageFull.ConfigInfo().Digest
	imageConfig, err := imageFull.OCIConfig(svc.ctx)
	if err != nil {
		return imageCacheItem{}, err
	}
	size := imageSize(imageFull)

	info, err := imageFull.Inspect(svc.ctx)
	if err != nil {
		return imageCacheItem{}, fmt.Errorf("inspecting image: %w", err)
	}

	rawSource, err := ref.NewImageSource(svc.ctx, systemContext)
	if err != nil {
		return imageCacheItem{}, err
	}
	defer rawSource.Close()

	topManifestBlob, manifestType, err := rawSource.GetManifest(svc.ctx, nil)
	if err != nil {
		return imageCacheItem{}, err
	}
	var ociManifest specs.Manifest
	if manifestType == specs.MediaTypeImageManifest {
		if err := json.Unmarshal(topManifestBlob, &ociManifest); err != nil {
			return imageCacheItem{}, err
		}
	}

	return imageCacheItem{
		config:       imageConfig,
		size:         size,
		configDigest: configDigest,
		info:         info,
		annotations:  ociManifest.Annotations,
	}, nil
}

func (svc *imageService_oci) buildImageResult(image *storage.Image, cacheItem imageCacheItem) ImageResult {
	name, tags, digests := sortNamesByType(image.Names)
	imageDigest, repoDigests := svc.makeRepoDigests(digests, tags, image)
	sort.Strings(tags)
	sort.Strings(repoDigests)
	previousName := ""
	if len(image.NamesHistory) > 0 {
		// Remove the tag because we can only keep the name as indicator
		split := strings.SplitN(image.NamesHistory[0], ":", 2)
		if len(split) > 0 {
			previousName = split[0]
		}
	}

	return ImageResult{
		ID:           image.ID,
		Name:         name,
		RepoTags:     tags,
		RepoDigests:  repoDigests,
		Size:         cacheItem.size,
		Digest:       imageDigest,
		ConfigDigest: cacheItem.configDigest,
		User:         cacheItem.config.Config.User,
		PreviousName: previousName,
		Labels:       cacheItem.info.Labels,
		OCIConfig:    cacheItem.config,
		Annotations:  cacheItem.annotations,
	}
}

func (svc *imageService_oci) appendCachedResult(systemContext *types.SystemContext, ref types.ImageReference, image *storage.Image, results []ImageResult, newImageCache imageCache) ([]ImageResult, error) {
	var err error
	svc.imageCacheLock.Lock()
	cacheItem, ok := svc.imageCache[image.ID]
	svc.imageCacheLock.Unlock()
	if !ok {
		cacheItem, err = svc.buildImageCacheItem(systemContext, ref)
		if err != nil {
			return results, err
		}
		if newImageCache == nil {
			svc.imageCacheLock.Lock()
			svc.imageCache[image.ID] = cacheItem
			svc.imageCacheLock.Unlock()
		} else {
			newImageCache[image.ID] = cacheItem
		}
	} else if newImageCache != nil {
		newImageCache[image.ID] = cacheItem
	}

	return append(results, svc.buildImageResult(image, cacheItem)), nil
}

func (svc *imageService_oci) ListImages(systemContext *types.SystemContext, filter string) ([]ImageResult, error) {
	var results []ImageResult
	if filter != "" {
		// we never remove entries from cache unless unfiltered ListImages call is made. Is it safe?
		ref, err := svc.getRef(filter)
		if err != nil {
			return nil, err
		}
		if image, err := istorage.Transport.GetStoreImage(svc.store, ref); err == nil {
			results, err = svc.appendCachedResult(systemContext, ref, image, []ImageResult{}, nil)
			if err != nil {
				return nil, err
			}
		}
	} else {
		images, err := svc.store.Images()
		if err != nil {
			return nil, err
		}
		newImageCache := make(imageCache, len(images))
		for i := range images {
			image := &images[i]
			ref, err := istorage.Transport.ParseStoreReference(svc.store, "@"+image.ID)
			if err != nil {
				return nil, err
			}
			results, err = svc.appendCachedResult(systemContext, ref, image, results, newImageCache)
			if err != nil {
				// skip reporting errors if the images haven't finished pulling
				if os.IsNotExist(err) {
					donePulling := true
					for _, name := range image.Names {
						if _, ok := ImageBeingPulled.Load(name); ok {
							donePulling = false
							break
						}
					}
					if !donePulling {
						continue
					}
				}
				return nil, err
			}
		}
		// replace image cache with cache we just built
		// this invalidates all stale entries in cache
		svc.imageCacheLock.Lock()
		svc.imageCache = newImageCache
		svc.imageCacheLock.Unlock()
	}
	return results, nil
}

func (svc *imageService_oci) ImageStatus(systemContext *types.SystemContext, nameOrID string) (*ImageResult, error) {
	ref, err := svc.getRef(nameOrID)
	if err != nil {
		return nil, err
	}
	image, err := istorage.Transport.GetStoreImage(svc.store, ref)
	if err != nil {
		return nil, err
	}
	svc.imageCacheLock.Lock()
	cacheItem, ok := svc.imageCache[image.ID]
	svc.imageCacheLock.Unlock()

	if !ok {
		cacheItem, err = svc.buildImageCacheItem(systemContext, ref) // Single-use-only, not actually cached
		if err != nil {
			return nil, err
		}
	}

	result := svc.buildImageResult(image, cacheItem)
	return &result, nil
}

func imageSize(img types.Image) *uint64 {
	if sum, err := img.Size(); err == nil {
		usum := uint64(sum)
		return &usum
	}
	return nil
}

// remoteImageReference creates an image reference from an image string
func (svc *imageLookupService) remoteImageReference(imageName string) (types.ImageReference, error) {
	if imageName == "" {
		return nil, storage.ErrNotAnImage
	}

	srcRef, err := alltransports.ParseImageName(imageName)
	if err != nil {
		if svc.DefaultTransport == "" {
			return nil, err
		}
		srcRef2, err2 := alltransports.ParseImageName(svc.DefaultTransport + imageName)
		if err2 != nil {
			return nil, err
		}
		srcRef = srcRef2
	}
	return srcRef, nil
}

// prepareReference creates an image reference from an image string and returns an updated types.SystemContext (never nil) for the image
func (svc *imageLookupService) prepareReference(inputSystemContext *types.SystemContext, imageName string) (*types.SystemContext, types.ImageReference, error) {
	srcRef, err := svc.remoteImageReference(imageName)
	if err != nil {
		return nil, nil, err
	}

	sc := types.SystemContext{}
	if inputSystemContext != nil {
		sc = *inputSystemContext // A shallow copy
	}
	if srcRef.DockerReference() != nil {
		hostname := reference.Domain(srcRef.DockerReference())
		if secure := svc.isSecureIndex(hostname); !secure {
			sc.DockerInsecureSkipTLSVerify = types.OptionalBoolTrue
		}
	}
	return &sc, srcRef, nil
}

func (svc *imageService_oci) PrepareImage(inputSystemContext *types.SystemContext, imageName string) (types.ImageCloser, error) {
	systemContext, srcRef, err := svc.lookup.prepareReference(inputSystemContext, imageName)
	if err != nil {
		return nil, err
	}

	return srcRef.NewImage(svc.ctx, systemContext)
}

func (svc *imageService_oci) copyImage(systemContext *types.SystemContext, imageName, parentCgroup string, options *ImageCopyOptions) error {
	progress := options.Progress
	dest := imageName
	// the first argument DEST is not used by the re-execed command but it is useful for debugging as it
	// shows in the ps output.
	cmd := reexec.CommandContext(svc.ctx, "crio-copy-image", dest)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("error getting stdout pipe for image copy process: %w", err)
	}
	defer stdout.Close()

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("error getting stderr pipe for image copy process: %w", err)
	}
	defer stderr.Close()

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("error getting stdin pipe for image copy process: %w", err)
	}

	if _, err := alltransports.ParseImageName(imageName); err != nil {
		if svc.lookup.DefaultTransport == "" {
			return err
		}
		imageName = svc.lookup.DefaultTransport + imageName
	}

	stdinArguments := copyImageArgs{
		Lookup:        svc.lookup,
		SystemContext: systemContext,
		Options:       options,
		ImageName:     imageName,
		ParentCgroup:  parentCgroup,
		StoreOptions: storage.StoreOptions{
			RunRoot:            svc.store.RunRoot(),
			GraphRoot:          svc.store.GraphRoot(),
			GraphDriverName:    svc.store.GraphDriverName(),
			GraphDriverOptions: svc.store.GraphOptions(),
			UIDMap:             svc.store.UIDMap(),
			GIDMap:             svc.store.GIDMap(),
		},
		HasCollectMode: node.SystemdHasCollectMode(),
	}

	stdinArguments.Options.Progress = nil
	if err := cmd.Start(); err != nil {
		return err
	}
	if err := json.NewEncoder(stdin).Encode(&stdinArguments); err != nil {
		stdin.Close()
		if waitErr := cmd.Wait(); waitErr != nil {
			return fmt.Errorf("%v: %w", waitErr, err)
		}
		return fmt.Errorf("json encode to pipe failed: %w", err)
	}
	stdin.Close()

	go func() {
		decoder := json.NewDecoder(bufio.NewReader(stdout))
		if progress != nil {
			defer close(progress)
		}
		for decoder.More() {
			var p types.ProgressProperties
			if err := decoder.Decode(&p); err != nil {
				break
			}

			if progress != nil {
				progress <- p
			}
		}
	}()
	errOutput, errReadAll := io.ReadAll(stderr)
	if err := cmd.Wait(); err != nil {
		if errReadAll == nil && len(errOutput) > 0 {
			return fmt.Errorf("pull image: %s", string(errOutput))
		}
		return err
	}
	return nil
}

func (svc *imageService_oci) PullImage(systemContext *types.SystemContext, imageName string, inputOptions *ImageCopyOptions) (types.ImageReference, error) {
	options := *inputOptions // A shallow copy

	srcSystemContext, srcRef, destRef, err := svc.lookup.getReferences(options.SourceCtx, svc.store, imageName)
	if err != nil {
		return nil, err
	}
	options.SourceCtx = srcSystemContext

	if inputOptions.CgroupPull.UseNewCgroup {
		if err := svc.copyImage(systemContext, imageName, inputOptions.CgroupPull.ParentCgroup, &options); err != nil {
			return nil, err
		}
	} else {
		policy, err := signature.DefaultPolicy(systemContext)
		if err != nil {
			return nil, err
		}
		policyContext, err := signature.NewPolicyContext(policy)
		if err != nil {
			return nil, err
		}

		copyOptions := toCopyOptions(&options, inputOptions.Progress)

		if _, err = copy.Image(svc.ctx, policyContext, destRef, srcRef, copyOptions); err != nil {
			return nil, err
		}
	}
	return destRef, nil
}

func (svc *imageLookupService) getReferences(inputSystemContext *types.SystemContext, store storage.Store, imageName string) (_ *types.SystemContext, srcRef, destRef types.ImageReference, _ error) {
	srcSystemContext, srcRef, err := svc.prepareReference(inputSystemContext, imageName)
	if err != nil {
		return nil, nil, nil, err
	}

	dest := imageName
	if srcRef.DockerReference() != nil {
		dest = srcRef.DockerReference().String()
	}

	destRef, err = istorage.Transport.ParseStoreReference(store, dest)
	if err != nil {
		return nil, nil, nil, err
	}
	return srcSystemContext, srcRef, destRef, nil
}

func (svc *imageService_oci) UntagImage(systemContext *types.SystemContext, nameOrID string) error {
	ref, err := svc.getRef(nameOrID)
	if err != nil {
		return err
	}
	img, err := istorage.Transport.GetStoreImage(svc.store, ref)
	if err != nil {
		return err
	}

	if !strings.HasPrefix(img.ID, nameOrID) {
		namedRef, err := svc.lookup.remoteImageReference(nameOrID)
		if err != nil {
			return err
		}

		name := nameOrID
		if namedRef.DockerReference() != nil {
			name = namedRef.DockerReference().String()
		}

		prunedNames := 0
		for _, imgName := range img.Names {
			if imgName != name && imgName != nameOrID {
				prunedNames += 1
			}
		}

		if prunedNames > 0 {
			return svc.store.RemoveNames(img.ID, []string{name, nameOrID})
		}
	}

	return ref.DeleteImage(svc.ctx, systemContext)
}

func (svc *imageService_oci) GetStore() storage.Store {
	return svc.store
}

func (svc *imageLookupService) isSecureIndex(indexName string) bool {
	if index, ok := svc.IndexConfigs[indexName]; ok {
		return index.secure
	}

	host, _, err := net.SplitHostPort(indexName)
	if err != nil {
		// assume indexName is of the form `host` without the port and go on.
		host = indexName
	}

	addrs, err := net.LookupIP(host)
	if err != nil {
		ip := net.ParseIP(host)
		if ip != nil {
			addrs = []net.IP{ip}
		}

		// if ip == nil, then `host` is neither an IP nor it could be looked up,
		// either because the index is unreachable, or because the index is behind an HTTP proxy.
		// So, len(addrs) == 0 and we're not aborting.
	}

	// Try CIDR notation only if addrs has any elements, i.e. if `host`'s IP could be determined.
	for _, addr := range addrs {
		for _, ipnet := range svc.InsecureRegistryCIDRs {
			// check if the addr falls in the subnet
			if ipnet.Contains(addr) {
				return false
			}
		}
	}

	return true
}

// ResolveNames resolves an image name into a storage image ID or a fully-qualified image name (domain/repo/image:tag).
// Will only return an empty slice if err != nil.
func (svc *imageService_oci) ResolveNames(systemContext *types.SystemContext, imageName string) ([]string, error) {
	// _Maybe_ it's a truncated image ID.  Don't prepend a registry name, then.
	if len(imageName) >= minimumTruncatedIDLength && svc.store != nil {
		if img, err := svc.store.Image(imageName); err == nil && img != nil && strings.HasPrefix(img.ID, imageName) {
			// It's a truncated version of the ID of an image that's present in local storage;
			// we need to expand it.
			return []string{img.ID}, nil
		}
	}
	// This to prevent any image ID to go through this routine
	_, err := reference.ParseNormalizedNamed(imageName)
	if err != nil {
		if strings.Contains(err.Error(), "cannot specify 64-byte hexadecimal strings") {
			return nil, ErrCannotParseImageID
		}
		return nil, err
	}

	// Disable short name alias mode. Will enable it once we settle on a shortname alias table.
	disabled := types.ShortNameModeDisabled
	systemContext.ShortNameMode = &disabled
	resolved, err := shortnames.Resolve(systemContext, imageName)
	if err != nil {
		return nil, err
	}

	if desc := resolved.Description(); len(desc) > 0 {
		logrus.Info(desc)
	}

	images := make([]string, len(resolved.PullCandidates))
	for i := range resolved.PullCandidates {
		// Strip the tag from ambiguous image references that have a
		// digest as well (e.g.  `image:tag@sha256:123...`).  Such
		// image references are supported by docker but, due to their
		// ambiguity, explicitly not by containers/image.
		ref := resolved.PullCandidates[i].Value
		_, isTagged := ref.(reference.NamedTagged)
		canonical, isDigested := ref.(reference.Canonical)
		if isTagged && isDigested {
			canonical, err = reference.WithDigest(reference.TrimNamed(ref), canonical.Digest())
			if err != nil {
				return nil, err
			}
			ref = canonical
		}
		images[i] = ref.String()
	}

	return images, nil
}

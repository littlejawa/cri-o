package storage

import (
	"context"

	"github.com/cri-o/cri-o/internal/log"
	"go.podman.io/image/v5/types"
	"go.podman.io/storage"
)

// imageServiceVM is the ImageServer interface implementation that is more appropriate
// for VM based container runtimes.
type imageServiceVM struct {
	ctx context.Context

	// link to an ImageServer that is used to perform some of the image management
	// operations. This allows imageServiceVM to delegate the core image handling tasks
	// to the storage.ImageServer, while providing a VM-specific interface where
	// needed.
	storageImageServer ImageServer
}

// GetImageServiceVM creates a new imageServiceVM instance.
func GetImageServiceVM(ctx context.Context, imageServer ImageServer) ImageServer {
	return &imageServiceVM{
		ctx:                ctx,
		storageImageServer: imageServer,
	}
}

// ListImages returns list of all images.
func (i *imageServiceVM) ListImages(systemContext *types.SystemContext) ([]ImageResult, error) {
	log.Debugf(i.ctx, "ImageServiceVM.ListImages() start")
	defer log.Debugf(i.ctx, "ImageServiceVM.ListImages() end")
	return i.storageImageServer.ListImages(systemContext)
}

// ImageStatusByID returns status of a single image
func (i *imageServiceVM) ImageStatusByID(systemContext *types.SystemContext, id StorageImageID) (*ImageResult, error) {
	log.Debugf(i.ctx, "ImageServiceVM.ImageStatusByID() start")
	defer log.Debugf(i.ctx, "ImageServiceVM.ImageStatusByID() end")
	return i.storageImageServer.ImageStatusByID(systemContext, id)
}

// ImageStatusByName returns status of an image tagged with name.
func (i *imageServiceVM) ImageStatusByName(systemContext *types.SystemContext, name RegistryImageReference) (*ImageResult, error) {
	log.Debugf(i.ctx, "ImageServiceVM.ImageStatusByName() start")
	defer log.Debugf(i.ctx, "ImageServiceVM.ImageStatusByName() end")
	return i.storageImageServer.ImageStatusByName(systemContext, name)
}

// PullImage imports an image from the specified location.
//
// Arguments:
// - ctx: The context for controlling the function's execution
// - imageName: A RegistryImageReference representing the image to be pulled
// - options: Pointer to ImageCopyOptions, which contains various options for the image copy process
//
// Returns:
//   - A name@digest value referring to exactly the pulled image (the reference might become dangling if the image
//     is removed, but it will not ever match a different image). The value is suitable for PullImageResponse.ImageRef
//     and for ContainerConfig.Image.Image.
//   - error: An error object if pulling the image fails, otherwise nil
func (i *imageServiceVM) PullImage(ctx context.Context, imageName RegistryImageReference, options *ImageCopyOptions) (RegistryImageReference, error) {
	log.Debugf(i.ctx, "ImageServiceVM.PullImage() start")
	defer log.Debugf(i.ctx, "ImageServiceVM.PullImage() end")
	return i.storageImageServer.PullImage(ctx, imageName, options)
}

// DeleteImage deletes a storage image (impacting all its tags)
func (i *imageServiceVM) DeleteImage(systemContext *types.SystemContext, id StorageImageID) error {
	log.Debugf(i.ctx, "ImageServiceVM.DeleteImage() start")
	defer log.Debugf(i.ctx, "ImageServiceVM.DeleteImage() end")
	return i.storageImageServer.DeleteImage(systemContext, id)
}

// UntagImage removes a name from the specified image, and if it was
// the only name the image had, removes the image.
func (i *imageServiceVM) UntagImage(systemContext *types.SystemContext, name RegistryImageReference) error {
	log.Debugf(i.ctx, "ImageServiceVM.UntagImage() start")
	defer log.Debugf(i.ctx, "ImageServiceVM.UntagImage() end")
	return i.storageImageServer.UntagImage(systemContext, name)
}

// GetStore returns the reference to the storage library Store which
// the image server uses to hold images, and is the destination used
// when it's asked to pull an image.
func (i *imageServiceVM) GetStore() storage.Store {
	log.Debugf(i.ctx, "ImageServiceVM.GetStore() start")
	defer log.Debugf(i.ctx, "ImageServiceVM.GetStore() end")
	return i.storageImageServer.GetStore()
}

// HeuristicallyTryResolvingStringAsIDPrefix checks if heuristicInput could be a valid image ID or a prefix, and returns
// a StorageImageID if so, or nil if the input can be something else.
// DO NOT CALL THIS from in-process callers who know what their input is and don't NEED to involve heuristics.
func (i *imageServiceVM) HeuristicallyTryResolvingStringAsIDPrefix(heuristicInput string) *StorageImageID {
	log.Debugf(i.ctx, "ImageServiceVM.HeuristicallyTryResolvingStringAsIDPrefix() start")
	defer log.Debugf(i.ctx, "ImageServiceVM.HeuristicallyTryResolvingStringAsIDPrefix() end")
	return i.storageImageServer.HeuristicallyTryResolvingStringAsIDPrefix(heuristicInput)
}

// CandidatesForPotentiallyShortImageName resolves an image name into a set of fully-qualified image names (domain/repo/image:tag|@digest).
// It will only return an empty slice if err != nil.
func (i *imageServiceVM) CandidatesForPotentiallyShortImageName(systemContext *types.SystemContext, imageName string) ([]RegistryImageReference, error) {
	log.Debugf(i.ctx, "ImageServiceVM.CandidatesForPotentiallyShortImageName() start")
	defer log.Debugf(i.ctx, "ImageServiceVM.CandidatesForPotentiallyShortImageName() end")
	return i.storageImageServer.CandidatesForPotentiallyShortImageName(systemContext, imageName)
}

// UpdatePinnedImagesList updates pinned and pause images list in imageService.
func (i *imageServiceVM) UpdatePinnedImagesList(imageList []string) {
	log.Debugf(i.ctx, "ImageServiceVM.UpdatePinnedImagesList() start")
	defer log.Debugf(i.ctx, "ImageServiceVM.UpdatePinnedImagesList() end")
	i.storageImageServer.UpdatePinnedImagesList(imageList)
}

// IsRunningImageAllowed verifies if running of the container image is allowed.
//
// Arguments:
// - ctx: The context for controlling the function's execution
// - systemContext: server's system context for the given namespace, notably it might have a customized SignaturePolicyPath.
// - userSpecifiedImage: a RegistryImageReference that expresses users’ _intended_ image.
// - imageID: A StorageImageID of the image
func (i *imageServiceVM) IsRunningImageAllowed(ctx context.Context, systemContext *types.SystemContext, userSpecifiedImage RegistryImageReference, imageID StorageImageID) error {
	log.Debugf(i.ctx, "ImageServiceVM.IsRunningImageAllowed() start")
	defer log.Debugf(i.ctx, "ImageServiceVM.IsRunningImageAllowed() end")
	return i.storageImageServer.IsRunningImageAllowed(ctx, systemContext, userSpecifiedImage, imageID)
}

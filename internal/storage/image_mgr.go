package storage

import (
	"context"

	"github.com/cri-o/cri-o/pkg/config"
	"go.podman.io/storage"
)

// The ImageServiceManager object is responsible for maintaining different
// implementations of the ImageServer interface.
// It allows for easy switching between different image storage backends
// depending on the configuration or environment.
type ImageServiceManager struct {
	serverConfig   *config.Config
	imageService   *imageService
	imageServiceVM *imageServiceVM
}

func (i *ImageServiceManager) GetImageService(runtimeHandler string) ImageServer {
	isRuntimePullImage := false
	if runtimeHandler != "" {
		r, ok := i.serverConfig.Runtimes[runtimeHandler]
		if ok {
			isRuntimePullImage = r.RuntimePullImage
		}
	}
	if isRuntimePullImage {
		return i.imageServiceVM
	}
	return i.imageServiceVM
}

func GetImageServiceManager(ctx context.Context, store storage.Store, storageTransport StorageTransport, serverConfig *config.Config) (*ImageServiceManager, error) {
	is, err := GetImageService(ctx, store, storageTransport, serverConfig)
	if err != nil {
		return nil, err
	}

	is_vm := GetImageServiceVM(ctx, is.(*imageService))

	return &ImageServiceManager{
		serverConfig:   serverConfig,
		imageService:   is.(*imageService),
		imageServiceVM: is_vm.(*imageServiceVM),
	}, nil
}

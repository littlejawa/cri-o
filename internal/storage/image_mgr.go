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
	imageService *imageService
}

func (i *ImageServiceManager) GetImageService() ImageServer {
	return i.imageService
}

func GetImageServiceManager(ctx context.Context, store storage.Store, storageTransport StorageTransport, serverConfig *config.Config) (*ImageServiceManager, error) {
	is, err := GetImageService(ctx, store, storageTransport, serverConfig)
	if err != nil {
		return nil, err
	}

	return &ImageServiceManager{
		imageService: is.(*imageService),
	}, nil
}

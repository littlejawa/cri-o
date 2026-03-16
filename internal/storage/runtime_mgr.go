package storage

import "context"

// The runtimeServiceManager object is responsible for maintaining different
// instances of runtimeService.
// It allows for easy switching between different runtime services using different
// image service managers in the backend.
type RuntimeServiceManager struct {
	runtimeService   *runtimeService
	runtimeServiceVM *runtimeService
}

func (r *RuntimeServiceManager) GetRuntimeService() RuntimeServer {
	return r.runtimeService
}

func GetRuntimeServiceManager(ctx context.Context, imageServiceMgr *ImageServiceManager, storageTransport StorageTransport) *RuntimeServiceManager {
	rs := GetRuntimeService(ctx, imageServiceMgr.imageService, storageTransport)
	rs_vm := GetRuntimeService(ctx, imageServiceMgr.imageServiceVM, storageTransport)
	return &RuntimeServiceManager{
		runtimeService:   rs.(*runtimeService),
		runtimeServiceVM: rs_vm.(*runtimeService),
	}
}

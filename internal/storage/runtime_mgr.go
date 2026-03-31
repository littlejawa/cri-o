package storage

import "context"

// The runtimeServiceManager object is responsible for maintaining different
// instances of runtimeService.
// It allows for easy switching between different runtime services using different
// image service managers in the backend.
type RuntimeServiceManager struct {
	runtimeService   *runtimeService
	runtimeServiceVM *runtimeServiceVM
}

func (r *RuntimeServiceManager) GetRuntimeService() RuntimeServer {
	return r.runtimeServiceVM
}

func GetRuntimeServiceManager(ctx context.Context, imageServiceMgr *ImageServiceManager, storageTransport StorageTransport) *RuntimeServiceManager {
	rs := GetRuntimeService(ctx, imageServiceMgr.imageService, storageTransport)
	rs_vm := GetRuntimeServiceVM(ctx, rs, imageServiceMgr.imageServiceVM, storageTransport)
	return &RuntimeServiceManager{
		runtimeService:   rs.(*runtimeService),
		runtimeServiceVM: rs_vm.(*runtimeServiceVM),
	}
}

package export

import (
	"context"

	castaipb "github.com/castai/kvisor/api/v1/runtime"
)

type DataBatchWriter interface {
	Write(ctx context.Context, req *castaipb.WriteDataBatchRequest) error
	Name() string
}

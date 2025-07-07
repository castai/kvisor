package castai

import (
	"context"
	"time"

	castaipb "github.com/castai/kvisor/api/v1/runtime"
	"github.com/castai/kvisor/cmd/agent/daemon/export"
	"github.com/castai/kvisor/pkg/castai"
	"github.com/castai/kvisor/pkg/logging"
	"github.com/cenkalti/backoff/v5"
	"google.golang.org/grpc"
)

func NewDataBatchWriter(client *castai.Client, log *logging.Logger) export.DataBatchWriter {
	return &dataBatchWriter{
		client: client,
		log:    log,
	}
}

type dataBatchWriter struct {
	client *castai.Client
	log    *logging.Logger
}

func (c *dataBatchWriter) Name() string {
	return "castai"
}

func (c *dataBatchWriter) Write(ctx context.Context, req *castaipb.WriteDataBatchRequest) error {
	_, err := backoff.Retry(
		ctx,
		func() (bool, error) {
			_, err := c.client.GRPC.WriteDataBatch(ctx, req, grpc.UseCompressor(c.client.GetCompressionName()))
			return true, err
		},
		backoff.WithMaxTries(3),
		backoff.WithBackOff(backoff.NewConstantBackOff(time.Second)),
		backoff.WithNotify(func(err error, duration time.Duration) {
			if err != nil {
				c.log.Warnf("writing data batch to castai: %v", err)
			}
		}),
	)
	return err
}

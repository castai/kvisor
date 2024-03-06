package imagescan

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	castaipb "github.com/castai/kvisor/api/v1/runtime"
	imagescanconfig "github.com/castai/kvisor/cmd/agent/imagescan/config"
	"github.com/castai/kvisor/pkg/metrics"
	"google.golang.org/grpc"

	"github.com/castai/kvisor/cmd/controller/kube"
	"github.com/castai/kvisor/pkg/logging"
	"github.com/samber/lo"
	"k8s.io/apimachinery/pkg/api/resource"
)

type castaiClient interface {
	GetSyncState(ctx context.Context, in *castaipb.GetSyncStateRequest, opts ...grpc.CallOption) (*castaipb.GetSyncStateResponse, error)
	UpdateSyncState(ctx context.Context, in *castaipb.UpdateSyncStateRequest, opts ...grpc.CallOption) (*castaipb.UpdateSyncStateResponse, error)
}

type Config struct {
	Enabled                   bool
	CastaiSecretRefName       string
	ScanInterval              time.Duration `validate:"required"`
	ScanTimeout               time.Duration
	MaxConcurrentScans        int64 `validate:"required"`
	ScanJobImagePullPolicy    string
	Mode                      string
	CPURequest                string
	CPULimit                  string
	MemoryRequest             string
	MemoryLimit               string
	ProfileEnabled            bool
	PhlareEnabled             bool
	PrivateRegistryPullSecret string
	InitDelay                 time.Duration
	CastaiGrpcInsecure        bool
	ImageScanBlobsCacheURL    string
}

type ImageScanImage struct {
	PullPolicy string `envconfig:"IMAGE_SCAN_IMAGE_PULL_POLICY" yaml:"pullPolicy"`
}

func NewController(
	log *logging.Logger,
	cfg Config,
	imageScanner imageScanner,
	client castaiClient,
	kubeController kubeClient,
) *Controller {
	log = log.WithField("component", "imagescan")
	return &Controller{
		imageScanner:      imageScanner,
		client:            client,
		kubeController:    kubeController,
		delta:             newDeltaState(kubeController),
		log:               log,
		cfg:               cfg,
		timeGetter:        timeGetter(),
		initialScansDelay: cfg.InitDelay,
	}
}

func timeGetter() func() time.Time {
	return func() time.Time {
		return time.Now().UTC()
	}
}

type Controller struct {
	delta          *deltaState
	imageScanner   imageScanner
	client         castaiClient
	kubeController kubeClient
	log            *logging.Logger
	cfg            Config
	timeGetter     func() time.Time

	initialScansDelay time.Duration
	fullSnapshotSent  bool
}

func (c *Controller) Run(ctx context.Context) error {
	c.log.Info("running")
	defer c.log.Infof("stopping")

	// Before starting normal scans and deltas processing
	// we need to spend some time processing only deltas to make sure
	// we have full images view.
	if err := c.waitInitialDeltaQueueSync(ctx); err != nil {
		return err
	}

	scanTicker := time.NewTicker(c.cfg.ScanInterval)
	defer scanTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case deltaItem := <-c.delta.queue:
			c.handleDelta(deltaItem.event, deltaItem.obj)
		case <-scanTicker.C:
			if err := c.scheduleScans(ctx); err != nil {
				c.log.Errorf("images scan failed: %v", err)
			}
		}
	}
}

func (c *Controller) waitInitialDeltaQueueSync(ctx context.Context) error {
	waitTimeout := time.After(c.initialScansDelay)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case deltaItem := <-c.delta.queue:
			c.handleDelta(deltaItem.event, deltaItem.obj)
		case <-waitTimeout:
			return nil
		}
	}
}

func (c *Controller) OnAdd(obj kube.Object) {
	c.delta.queue <- deltaQueueItem{
		event: kube.EventAdd,
		obj:   obj,
	}
}

func (c *Controller) OnUpdate(obj kube.Object) {
	c.delta.queue <- deltaQueueItem{
		event: kube.EventUpdate,
		obj:   obj,
	}
}

func (c *Controller) OnDelete(obj kube.Object) {
	c.delta.queue <- deltaQueueItem{
		event: kube.EventDelete,
		obj:   obj,
	}
}

func (c *Controller) handleDelta(event kube.EventType, o kube.Object) {
	switch event {
	case kube.EventAdd, kube.EventUpdate:
		c.delta.upsert(o)
	case kube.EventDelete:
		c.delta.delete(o)
	}
}

func (c *Controller) scheduleScans(ctx context.Context) (rerr error) {
	c.syncFromRemoteState(ctx)

	if err := c.updateImageStatuses(ctx); err != nil {
		c.log.Errorf("sending images resources changes: %v", err)
	}

	// Scan pending images.
	pendingImages := c.findPendingImages()
	concurrentScans := c.concurrentScansNumber()
	imagesForScan := pendingImages
	if len(imagesForScan) > concurrentScans {
		imagesForScan = imagesForScan[:concurrentScans]
	}
	if l := len(imagesForScan); l > 0 {
		c.log.Infof("scheduling %d images scans", l)
		if err := c.scanImages(ctx, imagesForScan); err != nil {
			return err
		}
		c.log.Info("images scan finished")
	} else {
		c.log.Debug("skipping images scan, no pending images")
	}

	return nil
}

func (c *Controller) findPendingImages() []*image {
	images := c.delta.getImages()

	now := c.timeGetter()

	privateImagesCount := lo.CountBy(images, func(v *image) bool {
		return isImagePrivate(v)
	})
	pendingImages := lo.Filter(images, func(v *image, _ int) bool {
		return isImagePending(v, now)
	})
	sort.Slice(pendingImages, func(i, j int) bool {
		return pendingImages[i].failures < pendingImages[j].failures
	})
	c.log.Infof("found %d images, pending images %d", len(images), len(pendingImages))
	metrics.ControllerImagesCount.Set(float64(len(images)))
	metrics.ControllerPendingImagesCount.Set(float64(len(pendingImages)))
	if privateImagesCount > 0 {
		c.log.Warnf("skipping %d private images", privateImagesCount)
	}
	return pendingImages
}

func (c *Controller) scanImages(ctx context.Context, images []*image) error {
	var wg sync.WaitGroup
	for _, img := range images {
		if img.name == "" {
			return fmt.Errorf("no image name set, image_id=%s", img.id)
		}

		wg.Add(1)
		go func(img *image) {
			defer wg.Done()

			if ctx.Err() != nil {
				return
			}

			ctx, cancel := context.WithTimeout(ctx, c.cfg.ScanTimeout)
			defer cancel()

			log := c.log.WithField("image", img.name)
			log.Info("scanning image")
			if err := c.scanImage(ctx, img); err != nil {
				log.Errorf("image scan failed: %v", err)
				parsedErr := parseErrorFromLog(err)
				c.delta.setImageScanError(img, parsedErr)
				if err := c.updateImageStatusAsFailed(ctx, img, parsedErr); err != nil {
					c.log.Errorf("sending images resources changes: %v", err)
				}
				return
			}
			log.Info("image scan finished")
			c.delta.updateImage(img, func(i *image) { i.scanned = true })
		}(img)
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *Controller) findBestNodeAndMode(img *image) (string, string, error) {
	mode := c.cfg.Mode
	if img.lastScanErr != nil && errors.Is(img.lastScanErr, errImageScanLayerNotFound) {
		// Fallback to remote if previously it failed due to missing layers.
		c.log.Debugf("selecting remote mode because of lastScanErr")
		mode = string(imagescanconfig.ModeRemote)
	}

	var nodeNames []string
	if imagescanconfig.Mode(mode) == imagescanconfig.ModeHostFS {
		// In HostFS we need to choose only from nodes which contains this image.
		nodeNames = lo.Keys(img.nodes)
		if len(nodeNames) == 0 {
			return "", "", errors.New("image with empty nodes")
		}

		nodeNames = c.delta.filterCastAIManagedNodes(nodeNames)
		if len(nodeNames) == 0 {
			// If image is not running on CAST AI managed nodes fallback to remote scan.
			mode = string(imagescanconfig.ModeRemote)
			c.log.Debugf("selecting remote mode because no CAST AI managed nodes found")
			nodeNames = lo.Keys(c.delta.nodes)
		}
	} else {
		nodeNames = lo.Keys(c.delta.nodes)
	}

	// skipping non-linux nodes as they are not supported as for today
	nodeNames = c.filterWindowsNodes(nodeNames)

	// Resolve best node.
	memQty := resource.MustParse(c.cfg.MemoryRequest)
	cpuQty := resource.MustParse(c.cfg.CPURequest)
	resolvedNode, err := c.delta.findBestNode(nodeNames, memQty.AsDec(), cpuQty.AsDec())
	if err != nil {
		if errors.Is(err, errNoCandidates) && imagescanconfig.Mode(mode) == imagescanconfig.ModeHostFS {
			// if mode was host fs fallback to remote scan and try picking node again.
			mode = string(imagescanconfig.ModeRemote)
			c.log.Debugf("selecting a node in remote mode because of errNoCandidates")
			nodeNames = lo.Keys(c.delta.nodes)
			resolvedNode, err = c.delta.findBestNode(nodeNames, memQty.AsDec(), cpuQty.AsDec())
			if err != nil {
				return "", "", err
			}
		} else {
			return "", "", err
		}
	}

	return resolvedNode, mode, nil
}

func (c *Controller) filterWindowsNodes(names []string) []string {
	var filtered []string
	for _, name := range names {
		if c.delta.nodes[name].os != "linux" {
			c.log.Debugf("skipping non-linux node %s", name)
			continue
		}
		filtered = append(filtered, name)
	}
	return filtered
}

func (c *Controller) scanImage(ctx context.Context, img *image) (rerr error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	node, mode, err := c.findBestNodeAndMode(img)
	if err != nil {
		return err
	}

	agentImageDetails, found := c.kubeController.GetKvisorAgentImageDetails()
	if !found {
		return errors.New("kvisor image details not found")
	}

	return c.imageScanner.ScanImage(ctx, ScanImageParams{
		ImageName:                   img.name,
		ImageID:                     img.id,
		ContainerRuntime:            string(img.containerRuntime),
		Mode:                        mode,
		ResourceIDs:                 lo.Keys(img.owners),
		NodeName:                    node,
		DeleteFinishedJob:           true,
		WaitForCompletion:           true,
		WaitDurationAfterCompletion: 30 * time.Second,
		Architecture:                img.architecture,
		Os:                          img.os,
		ScanImageDetails:            agentImageDetails,
	})
}

func (c *Controller) concurrentScansNumber() int {
	if c.delta.nodeCount() == 1 {
		return 1
	}

	return int(c.cfg.MaxConcurrentScans)
}

func (c *Controller) updateImageStatuses(ctx context.Context) error {
	images := c.delta.getImages()
	if c.fullSnapshotSent {
		images = lo.Filter(images, func(item *image, index int) bool {
			return item.ownerChangedAt.After(item.resourcesUpdatedAt)
		})
	}
	if len(images) == 0 {
		return nil
	}
	now := c.timeGetter()
	var imagesChanges []*castaipb.Image
	for _, img := range images {
		resourceIds := lo.Keys(img.owners)

		var updatedStatus castaipb.ImageScanStatus
		if isImagePending(img, now) {
			updatedStatus = castaipb.ImageScanStatus_IMAGE_SCAN_STATUS_PENDING
		}
		imagesChanges = append(imagesChanges, &castaipb.Image{
			Id:           img.id,
			Architecture: img.architecture,
			ResourceIds:  resourceIds,
			Name:         img.name,
			ScanStatus:   updatedStatus,
		})
	}

	c.log.Info("sending images sync state")
	report := &castaipb.UpdateSyncStateRequest{
		FullSnapshot: !c.fullSnapshotSent,
		Images:       imagesChanges,
	}
	_, err := c.client.UpdateSyncState(ctx, report)
	if err != nil {
		return err
	}
	for _, img := range images {
		img.resourcesUpdatedAt = now
	}
	c.fullSnapshotSent = true
	return nil
}

func (c *Controller) updateImageStatusAsFailed(ctx context.Context, image *image, scanJobError error) error {
	if image == nil {
		return errors.New("image is missing")
	}
	var errorMsg string
	if scanJobError != nil {
		errorMsg = scanJobError.Error()
	}

	updatedImage := &castaipb.Image{
		Id:           image.id,
		Name:         image.name,
		Architecture: image.architecture,
		ScanStatus:   castaipb.ImageScanStatus_IMAGE_SCAN_STATUS_SCAN_ERROR,
		ScanError:    errorMsg,
	}

	c.log.Info("sending image failed status")
	req := &castaipb.UpdateSyncStateRequest{
		Images: []*castaipb.Image{updatedImage},
	}
	_, err := c.client.UpdateSyncState(ctx, req)
	return err
}

func (c *Controller) syncFromRemoteState(ctx context.Context) {
	images := c.delta.getImages()
	now := c.timeGetter().UTC()
	imagesWithNotSyncedState := lo.Filter(images, func(item *image, index int) bool {
		return !item.scanned && item.lastRemoteSyncAt.Before(now.Add(-10*time.Minute))
	})

	if len(imagesWithNotSyncedState) == 0 {
		return
	}

	imagesIds := lo.Map(imagesWithNotSyncedState, func(item *image, index int) string {
		return item.id
	})
	c.log.Debugf("sync images state from remote")
	resp, err := c.client.GetSyncState(ctx, &castaipb.GetSyncStateRequest{ImageIds: imagesIds})
	if err != nil {
		c.log.Errorf("getting images sync state from remote: %v", err)
		return
	}
	if resp.Images == nil {
		return
	}

	// Set sync state for all these images to prevent constant api calls.
	for _, img := range imagesWithNotSyncedState {
		img.lastRemoteSyncAt = now
	}
	// Set images as scanned from remote response.
	for _, remoteImage := range resp.Images.Images {
		if remoteImage.ScanStatus == castaipb.ImageScanStatus_IMAGE_SCAN_STATUS_SCANNED {
			c.delta.setImageScanned(remoteImage)
		}
	}

	// If full resources resync is required it will be sent during next scheduled scan.
	if resp.Images.FullResyncRequired {
		c.fullSnapshotSent = false
	}
	c.log.Infof("images updated from remote state, full_resync=%v, scanned_images=%d", resp.Images.FullResyncRequired, len(resp.Images.Images))
}

func isImagePending(v *image, now time.Time) bool {
	return !v.scanned &&
		len(v.owners) > 0 &&
		!isImagePrivate(v) &&
		(v.nextScan.IsZero() || v.nextScan.Before(now))
}

func isImagePrivate(v *image) bool {
	return errors.Is(v.lastScanErr, errPrivateImage)
}

package gcp

import (
	"context"
	"errors"
	"fmt"
	"math"
	"path"
	"strings"

	"cloud.google.com/go/compute/apiv1/computepb"
	"github.com/samber/lo"
	"google.golang.org/api/iterator"

	"github.com/castai/kvisor/pkg/cloudprovider/types"
)

func (p *Provider) GetStorageState(ctx context.Context, instanceIds ...string) (*types.StorageState, error) {
	p.log.Debug("refreshing storage state")

	state := &types.StorageState{
		Domain:          "googleapis.com",
		Provider:        types.TypeGCP,
		InstanceVolumes: make(map[string][]types.Volume),
	}

	instanceVolumes, err := p.fetchInstanceVolumes(ctx, instanceIds...)
	if err != nil {
		return nil, fmt.Errorf("fetching volumes: %w", err)
	}
	state.InstanceVolumes = instanceVolumes

	p.storageStateMu.Lock()
	defer p.storageStateMu.Unlock()
	p.storageState = state

	return p.storageState, nil
}

// fetchInstanceVolumes retrieves instance volumes from https://docs.cloud.google.com/compute/docs/reference/rest/v1/disks/aggregatedList
func (p *Provider) fetchInstanceVolumes(ctx context.Context, instanceIds ...string) (map[string][]types.Volume, error) {
	instanceVolumes := make(map[string][]types.Volume, len(instanceIds))

	if len(instanceIds) == 0 {
		return instanceVolumes, nil
	}

	instanceUrlsMap := make(map[string]string, len(instanceIds))
	for _, instanceId := range instanceIds {
		url := buildInstanceUrlFromId(instanceId)
		instanceUrlsMap[url] = instanceId
	}

	filter := buildDisksUsedByInstanceFilter(lo.Keys(instanceUrlsMap))

	req := &computepb.AggregatedListDisksRequest{
		Project: p.cfg.GCPProjectID,
		Filter:  &filter,
	}

	it := p.disksClient.AggregatedList(ctx, req)
	for {
		result, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			return instanceVolumes, fmt.Errorf("listing disks: %w", err)
		}

		for _, disk := range result.Value.Disks {
			if disk.Name == nil {
				continue
			}

			for _, instanceUrl := range disk.Users {
				instanceId, ok := instanceUrlsMap[instanceUrl]
				if !ok {
					continue
				}

				volume := types.Volume{
					VolumeID:    disk.GetName(),
					VolumeState: strings.ToLower(disk.GetStatus()),
					Encrypted:   true, // GCP disks are encrypted by default
				}

				if disk.GetType() != "" {
					volume.VolumeType = path.Base(disk.GetType())
				}

				if disk.GetZone() != "" {
					volume.Zone = path.Base(disk.GetZone())
				}

				if disk.GetSizeGb() > 0 {
					// Size is in GB, convert to bytes
					volume.SizeBytes = disk.GetSizeGb() * 1024 * 1024 * 1024
				}

				if disk.GetProvisionedIops() > 0 {
					volume.IOPS = safeInt64ToInt32(disk.GetProvisionedIops())
				}

				if disk.GetProvisionedThroughput() > 0 {
					// Throughput is in MB/s, convert to bytes/s
					volume.ThroughputBytes = safeInt64ToInt32(disk.GetProvisionedThroughput() * 1024 * 1024)
				}

				instanceVolumes[instanceId] = append(instanceVolumes[instanceId], volume)
			}
		}
	}

	return instanceVolumes, nil
}

// buildInstanceUrlFromId converts an instance ID (project/zone/instance-name) to a full GCP instance URL
func buildInstanceUrlFromId(instanceId string) string {
	parts := strings.Split(instanceId, "/")
	if len(parts) != 3 {
		return ""
	}
	return fmt.Sprintf("https://www.googleapis.com/compute/v1/projects/%s/zones/%s/instances/%s", parts[0], parts[1], parts[2])
}

// buildDisksUsedByInstanceFilter builds a GCP API filter for disks attached to specific instances
func buildDisksUsedByInstanceFilter(instanceUrls []string) string {
	conditions := make([]string, len(instanceUrls))
	for i, url := range instanceUrls {
		conditions[i] = fmt.Sprintf(`(users:%q)`, url)
	}
	return strings.Join(conditions, " OR ")
}

func safeInt64ToInt32(val int64) int32 {
	if val > math.MaxInt32 {
		return math.MaxInt32
	}
	return int32(val) // nolint:gosec
}

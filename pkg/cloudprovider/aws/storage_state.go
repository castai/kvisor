package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/castai/kvisor/pkg/cloudprovider/types"
)

func (p *Provider) GetStorageState(ctx context.Context) (*types.StorageState, error) {
	p.storageStateMu.RLock()
	defer p.storageStateMu.RUnlock()

	if p.storageState == nil {
		return nil, fmt.Errorf("storage state not yet available")
	}

	return p.storageState, nil
}

func (p *Provider) RefreshStorageState(ctx context.Context, instanceIds ...string) error {
	p.log.Debug("refreshing storage state")

	state := &types.StorageState{
		Domain:          "amazonaws.com",
		Provider:        types.TypeAWS,
		InstanceVolumes: make(map[string][]types.Volume),
	}

	instanceVolumes, err := p.fetchInstanceVolumes(ctx, instanceIds...)
	if err != nil {
		return fmt.Errorf("fetching volumes: %w", err)
	}
	state.InstanceVolumes = instanceVolumes

	p.storageStateMu.Lock()
	p.storageState = state
	p.storageStateMu.Unlock()

	p.log.Debug("refreshed storage state")
	return nil
}

// fetchInstanceVolumes retrieves instance volumes from https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_Volume.html
func (p *Provider) fetchInstanceVolumes(ctx context.Context, instanceIds ...string) (map[string][]types.Volume, error) {
	instanceVolumes := make(map[string][]types.Volume)

	if len(instanceIds) == 0 {
		return instanceVolumes, nil
	}

	input := &ec2.DescribeVolumesInput{
		Filters: []ec2types.Filter{
			{
				Name:   aws.String("attachment.instance-id"),
				Values: instanceIds,
			},
		},
	}

	result, err := p.ec2Client.DescribeVolumes(ctx, input)
	if err != nil {
		return instanceVolumes, fmt.Errorf("describing volumes: %w", err)
	}

	for _, vol := range result.Volumes {
		if vol.VolumeId == nil {
			continue
		}

		volume := types.Volume{
			VolumeID:    aws.ToString(vol.VolumeId),
			VolumeType:  string(vol.VolumeType),
			VolumeState: string(vol.State),
			Encrypted:   aws.ToBool(vol.Encrypted),
			Zone:        aws.ToString(vol.AvailabilityZone),
		}

		// Size is in GiB, convert to bytes
		if vol.Size != nil && *vol.Size > 0 {
			volume.SizeBytes = int64(*vol.Size) * 1024 * 1024 * 1024
		}

		// IOPS is only available for certain volume types (io1, io2, gp3)
		if vol.Iops != nil && *vol.Iops > 0 {
			volume.IOPS = *vol.Iops
		}

		// Throughput is only available for gp3 and st1/sc1 volume types
		if vol.Throughput != nil && *vol.Throughput > 0 {
			// Throughput is in MiB/s, convert to bytes/s
			volume.ThroughputBytes = *vol.Throughput * 1024 * 1024
		}

		for _, attachment := range vol.Attachments {
			if attachment.InstanceId != nil {
				instanceID := aws.ToString(attachment.InstanceId)
				instanceVolumes[instanceID] = append(instanceVolumes[instanceID], volume)
			}
		}
	}

	return instanceVolumes, nil
}

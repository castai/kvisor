package aws

import (
	"context"
	"fmt"
	"maps"
	"slices"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/castai/kvisor/pkg/cloudprovider/types"
)

const (
	instanceChunkSize = 20
)

func (p *Provider) GetStorageState(ctx context.Context, instanceIds ...string) (*types.StorageState, error) {
	p.log.Debug("refreshing storage state")

	state := &types.StorageState{
		Domain:   "amazonaws.com",
		Provider: types.TypeAWS,
	}

	instanceVolumes, err := p.chunkAndFetchInstanceVolumes(ctx, instanceIds...)
	if err != nil {
		return nil, fmt.Errorf("fetching volumes: %w", err)
	}
	state.InstanceVolumes = instanceVolumes

	return state, nil
}

// chunkAndFetchInstanceVolumes chunks instance IDs into smaller batches and fetches volumes for each batch
// to avoid API limits
func (p *Provider) chunkAndFetchInstanceVolumes(ctx context.Context, instanceIds ...string) (map[string][]types.Volume, error) {
	instanceVolumes := make(map[string][]types.Volume)

	if len(instanceIds) == 0 {
		return instanceVolumes, nil
	}

	for chunk := range slices.Chunk(instanceIds, instanceChunkSize) {
		chunkVolumes, err := p.fetchInstanceVolumes(ctx, chunk)
		if err != nil {
			return nil, err
		}

		maps.Copy(instanceVolumes, chunkVolumes)
	}

	return instanceVolumes, nil
}

// fetchInstanceVolumes retrieves instance volumes from https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_Volume.html
func (p *Provider) fetchInstanceVolumes(ctx context.Context, instanceIds []string) (map[string][]types.Volume, error) {
	instanceVolumes := make(map[string][]types.Volume)

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

		attachments := make(map[string]types.AWSVolumeDetails, len(vol.Attachments))
		for _, v := range vol.Attachments {
			if v.InstanceId == nil || v.Device == nil {
				continue
			}

			attachments[*v.InstanceId] = types.AWSVolumeDetails{
				Device: aws.ToString(v.Device),
			}
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
				instanceVolume := volume

				volDetails, found := attachments[instanceID]
				if found {
					instanceVolume.AwsDetails = &volDetails
				}

				instanceVolumes[instanceID] = append(instanceVolumes[instanceID], instanceVolume)
			}
		}
	}

	return instanceVolumes, nil
}

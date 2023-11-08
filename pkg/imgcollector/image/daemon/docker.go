// Trivy
// Copyright 2019-2020 Aqua Security Software Ltd.
// This product includes software developed by Aqua Security (https://aquasec.com).
//
// Adapted from https://github.com/aquasecurity/trivy

package daemon

import (
	"context"
	"fmt"
	"os"

	"github.com/docker/docker/client"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

// DockerImage implements v1.Image by extending daemon.Image.
// The caller must call cleanup() to remove a temporary file.
func DockerImage(ref name.Reference) (Image, func(), error) {
	cleanup := func() {}

	c, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, cleanup, fmt.Errorf("failed to initialize a docker client: %w", err)
	}
	defer func() {
		if err != nil {
			_ = c.Close()
		}
	}()

	// <image_name>:<tag> pattern like "alpine:3.15"
	// or
	// <image_name>@<digest> pattern like "alpine@sha256:21a3deaa0d32a8057914f36584b5288d2e5ecc984380bc0118285c70fa8c9300"
	imageID := ref.Name()
	inspect, _, err := c.ImageInspectWithRaw(context.Background(), imageID)
	if err != nil {
		imageID = ref.String() // <image_id> pattern like `5ac716b05a9c`
		inspect, _, err = c.ImageInspectWithRaw(context.Background(), imageID)
		if err != nil {
			return nil, cleanup, fmt.Errorf("unable to inspect the image (%s): %w", imageID, err)
		}
	}

	history, err := c.ImageHistory(context.Background(), imageID)
	if err != nil {
		return nil, cleanup, fmt.Errorf("unable to get history (%s): %w", imageID, err)
	}

	f, err := os.CreateTemp("", "fanal-*")
	if err != nil {
		return nil, cleanup, fmt.Errorf("failed to create a temporary file")
	}

	cleanup = func() {
		_ = c.Close()
		_ = f.Close()
		_ = os.Remove(f.Name())
	}

	return &image{
		opener:  imageOpener(context.Background(), imageID, f, c.ImageSave),
		inspect: inspect,
		history: configHistory(history),
	}, cleanup, nil
}

// DockerTarImage implements v1.Image by extending daemon.Image.
// The caller must call cleanup() to remove a temporary file.
func DockerTarImage(ref name.Reference, localTarPath string) (Image, func(), error) {
	cleanup := func() {}

	c, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, cleanup, fmt.Errorf("failed to initialize a docker client: %w", err)
	}
	defer func() {
		if err != nil {
			_ = c.Close()
		}
	}()

	// <image_name>:<tag> pattern like "alpine:3.15"
	// or
	// <image_name>@<digest> pattern like "alpine@sha256:21a3deaa0d32a8057914f36584b5288d2e5ecc984380bc0118285c70fa8c9300"
	imageID := ref.Name()
	inspect, _, err := c.ImageInspectWithRaw(context.Background(), imageID)
	if err != nil {
		imageID = ref.String() // <image_id> pattern like `5ac716b05a9c`
		inspect, _, err = c.ImageInspectWithRaw(context.Background(), imageID)
		if err != nil {
			return nil, cleanup, fmt.Errorf("unable to inspect the image (%s): %w", imageID, err)
		}
	}

	history, err := c.ImageHistory(context.Background(), imageID)
	if err != nil {
		return nil, cleanup, fmt.Errorf("unable to get history (%s): %w", imageID, err)
	}

	f, err := os.CreateTemp("", "fanal-*")
	if err != nil {
		return nil, cleanup, fmt.Errorf("failed to create a temporary file")
	}

	cleanup = func() {
		_ = c.Close()
		_ = f.Close()
		_ = os.Remove(f.Name())
	}

	return &image{
		opener: func() (v1.Image, error) {
			return tarball.ImageFromPath(localTarPath, nil)
		},
		inspect: inspect,
		history: configHistory(history),
	}, cleanup, nil
}

// Trivy
// Copyright 2019-2020 Aqua Security Software Ltd.
// This product includes software developed by Aqua Security (https://aquasec.com).
//
// Adapted from https://github.com/aquasecurity/trivy/blob/main/pkg/fanal/artifact/image/image.go in order to remove some checks and fix race conditions
// while scanning multiple images.

package image

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"sync"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	"github.com/aquasecurity/trivy/pkg/fanal/handler"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/fanal/walker"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/samber/lo"
	"github.com/sirupsen/logrus"
	"golang.org/x/exp/slices"
	"golang.org/x/sync/semaphore"

	"github.com/castai/kvisor/blobscache"
)

const (
	parallel = 5
)

type Artifact struct {
	log            logrus.FieldLogger
	image          types.Image
	cache          blobscache.Client
	walker         walker.LayerTar
	analyzer       analyzer.AnalyzerGroup
	handlerManager handler.Manager

	artifactOption artifact.Option
}

type ArtifactOption = artifact.Option

func NewArtifact(img types.Image, log logrus.FieldLogger, c blobscache.Client, opt artifact.Option) (*Artifact, error) {
	a, err := analyzer.NewAnalyzerGroup(analyzer.AnalyzerOptions{
		Group:             opt.AnalyzerGroup,
		DisabledAnalyzers: opt.DisabledAnalyzers,
	})
	if err != nil {
		return nil, fmt.Errorf("create analyzer group: %w", err)
	}

	return &Artifact{
		log:            log,
		image:          img,
		cache:          c,
		walker:         walker.NewLayerTar(opt.SkipFiles, opt.SkipDirs, opt.Slow),
		analyzer:       a,
		artifactOption: opt,
	}, nil
}

type ArtifactReference struct {
	BlobsInfo    []types.BlobInfo
	ConfigFile   *v1.ConfigFile
	ArtifactInfo *types.ArtifactInfo
	OsInfo       *types.OS
}

func (a Artifact) Inspect(ctx context.Context) (*ArtifactReference, error) {
	imageID, err := a.image.ID()
	if err != nil {
		return nil, fmt.Errorf("unable to get the image ID: %w", err)
	}

	diffIDs, err := a.image.LayerIDs()
	if err != nil {
		return nil, fmt.Errorf("unable to get layer IDs: %w", err)
	}

	configFile, err := a.image.ConfigFile()
	if err != nil {
		return nil, fmt.Errorf("unable to get the image's config file: %w", err)
	}

	a.log.Debugf("image ID: %s", imageID)
	a.log.Debugf("diff IDs: %v", diffIDs)

	// Try to detect base layers.
	baseDiffIDs := a.guessBaseLayers(diffIDs, configFile)
	a.log.Debugf("base layers: %v", baseDiffIDs)

	// Convert image ID and layer IDs to cache keys
	imageKey, layerKeys, layerKeyMap := a.calcCacheKeys(imageID, diffIDs)

	// Check if image os info already cached.
	cachedOSInfo, err := a.getCachedOsInfo(ctx, imageKey)
	if err != nil && !errors.Is(err, blobscache.ErrCacheNotFound) {
		return nil, err
	}
	var missingImageKey string
	if cachedOSInfo == nil {
		missingImageKey = imageKey
	}

	// Find cached layers
	cachedLayers, err := a.getCachedLayers(ctx, layerKeys)
	if err != nil {
		return nil, err
	}
	missingLayersKeys := lo.Filter(layerKeys, func(v string, _ int) bool {
		_, ok := cachedLayers[v]
		return !ok
	})
	a.log.Debugf("found %d cached layers, %d layers will be inspected", len(cachedLayers), len(missingLayersKeys))

	// Inspect all not cached layers.
	blobsInfo, artifactInfo, osInfo, err := a.inspect(ctx, missingImageKey, missingLayersKeys, baseDiffIDs, layerKeyMap)
	if err != nil {
		return nil, fmt.Errorf("analyze error: %w", err)
	}

	return &ArtifactReference{
		BlobsInfo:    append(blobsInfo, lo.Values(cachedLayers)...),
		ConfigFile:   configFile,
		ArtifactInfo: artifactInfo,
		OsInfo:       osInfo,
	}, nil
}

func (a Artifact) getCachedOsInfo(ctx context.Context, key string) (*types.ArtifactInfo, error) {
	blobBytes, err := a.cache.GetBlob(ctx, key)
	if err != nil {
		return nil, blobscache.ErrCacheNotFound
	}
	var res types.ArtifactInfo
	if err := json.Unmarshal(blobBytes, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

func (a Artifact) getCachedLayers(ctx context.Context, ids []string) (map[string]types.BlobInfo, error) {
	blobs := map[string]types.BlobInfo{}
	for _, id := range ids {
		blobBytes, err := a.cache.GetBlob(ctx, id)
		if err != nil && !errors.Is(err, blobscache.ErrCacheNotFound) {
			continue
		}
		if len(blobBytes) > 0 {
			var blob types.BlobInfo
			if err := json.Unmarshal(blobBytes, &blob); err != nil {
				return nil, err
			}
			blobs[id] = blob
		}
	}
	return blobs, nil
}

func (Artifact) Clean(_ types.ArtifactReference) error {
	return nil
}

func (a Artifact) calcCacheKeys(imageID string, diffIDs []string) (string, []string, map[string]string) {
	// Currently cache keys are mapped 1 to 1 with image id and blobs id.
	// If needed this logic can be extended to have custom cache keys.
	imageKey := imageID
	layerKeyMap := map[string]string{}
	var layerKeys []string
	for _, diffID := range diffIDs {
		blobKey := diffID
		layerKeys = append(layerKeys, diffID)
		layerKeyMap[blobKey] = diffID
	}
	return imageKey, layerKeys, layerKeyMap
}

func (a Artifact) inspect(ctx context.Context, missingImageKey string, layerKeys, baseDiffIDs []string, layerKeyMap map[string]string) ([]types.BlobInfo, *types.ArtifactInfo, *types.OS, error) {
	blobInfo := make(chan types.BlobInfo)

	errCh := make(chan error)
	limit := semaphore.NewWeighted(parallel)
	if a.artifactOption.Slow {
		// Inspect layers in series
		limit = semaphore.NewWeighted(1)
	}

	var osFound types.OS

	go func() {
		for _, k := range layerKeys {
			if err := limit.Acquire(ctx, 1); err != nil {
				errCh <- fmt.Errorf("semaphore acquire: %w", err)
				return
			}

			go func(ctx context.Context, layerKey string) {
				defer func() {
					limit.Release(1)
				}()

				diffID := layerKeyMap[layerKey]

				// If it is a base layer, secret scanning should not be performed.
				var disabledAnalyzers []analyzer.Type
				if slices.Contains(baseDiffIDs, diffID) {
					disabledAnalyzers = append(disabledAnalyzers, analyzer.TypeSecret)
				}

				layerInfo, err := a.inspectLayer(ctx, diffID, disabledAnalyzers)
				if err != nil {
					errCh <- fmt.Errorf("failed to analyze layer: %s : %w", diffID, err)
					return
				}

				layerBytes, err := json.Marshal(layerInfo)
				if err != nil {
					errCh <- err
					return
				}
				if err := a.cache.PutBlob(ctx, layerKey, layerBytes); err != nil {
					a.log.Warnf("putting blob to cache: %v", err)
				}

				if layerInfo.OS != nil {
					osFound = *layerInfo.OS
				}
				blobInfo <- layerInfo
			}(ctx, k)
		}
	}()

	blobsInfo := make([]types.BlobInfo, 0, len(layerKeys))

	for range layerKeys {
		select {
		case blob := <-blobInfo:
			blobsInfo = append(blobsInfo, blob)
		case err := <-errCh:
			return nil, nil, nil, err
		case <-ctx.Done():
			return nil, nil, nil, fmt.Errorf("timeout: %w", ctx.Err())
		}
	}

	var artifactInfo *types.ArtifactInfo
	if missingImageKey != "" {
		var err error
		artifactInfo, err = a.inspectConfig(ctx, missingImageKey, osFound)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("unable to analyze config: %w", err)
		}
	}

	return blobsInfo, artifactInfo, &osFound, nil
}

func (a Artifact) inspectLayer(ctx context.Context, diffID string, disabled []analyzer.Type) (types.BlobInfo, error) {
	a.log.Debugf("missing diff ID in cache: %s", diffID)

	layerDigest, r, err := a.uncompressedLayer(diffID)
	if err != nil {
		return types.BlobInfo{}, fmt.Errorf("unable to get uncompressed layer %s: %w", diffID, err)
	}

	// Prepare variables
	var wg sync.WaitGroup
	opts := analyzer.AnalysisOptions{Offline: a.artifactOption.Offline}
	result := analyzer.NewAnalysisResult()
	limit := semaphore.NewWeighted(parallel)
	if a.artifactOption.Slow {
		// Inspect layers in series
		limit = semaphore.NewWeighted(1)
	}

	// Walk a tar layer
	opqDirs, whFiles, err := a.walker.Walk(r, func(filePath string, info os.FileInfo, opener analyzer.Opener) error {
		if err = a.analyzer.AnalyzeFile(ctx, &wg, limit, result, "", filePath, info, opener, disabled, opts); err != nil {
			return fmt.Errorf("failed to analyze %s: %w", filePath, err)
		}
		return nil
	})
	if err != nil {
		return types.BlobInfo{}, fmt.Errorf("walk error: %w", err)
	}

	// Wait for all the goroutine to finish.
	wg.Wait()

	// Sort the analysis result for consistent results
	result.Sort()

	blobInfo := types.BlobInfo{
		SchemaVersion:   types.BlobJSONSchemaVersion,
		Digest:          layerDigest,
		DiffID:          diffID,
		OS:              result.OS,
		Repository:      result.Repository,
		PackageInfos:    result.PackageInfos,
		Applications:    result.Applications,
		Secrets:         result.Secrets,
		OpaqueDirs:      opqDirs,
		WhiteoutFiles:   whFiles,
		CustomResources: result.CustomResources,

		// For Red Hat
		BuildInfo: result.BuildInfo,
	}

	// Call post handlers to modify blob info
	if err = a.handlerManager.PostHandle(ctx, result, &blobInfo); err != nil {
		return types.BlobInfo{}, fmt.Errorf("post handler error: %w", err)
	}

	return blobInfo, nil
}

func (a Artifact) uncompressedLayer(diffID string) (string, io.Reader, error) {
	// diffID is a hash of the uncompressed layer
	h, err := v1.NewHash(diffID)
	if err != nil {
		return "", nil, fmt.Errorf("invalid layer ID (%s): %w", diffID, err)
	}

	layer, err := a.image.LayerByDiffID(h)
	if err != nil {
		return "", nil, fmt.Errorf("failed to get the layer (%s): %w", diffID, err)
	}

	// digest is a hash of the compressed layer
	var digest string
	if a.isCompressed(layer) {
		d, err := layer.Digest()
		if err != nil {
			return "", nil, fmt.Errorf("failed to get the digest (%s): %w", diffID, err)
		}
		digest = d.String()
	}

	r, err := layer.Uncompressed()
	if err != nil {
		return "", nil, fmt.Errorf("failed to get the layer content (%s): %w", diffID, err)
	}
	return digest, r, nil
}

// ref. https://github.com/google/go-containerregistry/issues/701
func (a Artifact) isCompressed(l v1.Layer) bool {
	_, uncompressed := reflect.TypeOf(l).Elem().FieldByName("UncompressedLayer")
	return !uncompressed
}

func (a Artifact) inspectConfig(ctx context.Context, imageID string, osFound types.OS) (*types.ArtifactInfo, error) {
	configBlob, err := a.image.RawConfigFile()
	if err != nil {
		return nil, fmt.Errorf("unable to get config blob: %w", err)
	}

	pkgs := a.analyzer.AnalyzeImageConfig(osFound, configBlob)

	var s1 v1.ConfigFile
	if err = json.Unmarshal(configBlob, &s1); err != nil {
		return nil, fmt.Errorf("json marshal error: %w", err)
	}

	info := types.ArtifactInfo{
		SchemaVersion:   types.ArtifactJSONSchemaVersion,
		Architecture:    s1.Architecture,
		Created:         s1.Created.Time,
		DockerVersion:   s1.DockerVersion,
		OS:              s1.OS,
		HistoryPackages: pkgs,
	}

	// Cache info.
	infoBytes, err := json.Marshal(info)
	if err != nil {
		return nil, err
	}
	if err := a.cache.PutBlob(ctx, imageID, infoBytes); err != nil {
		a.log.Warnf("putting config cache blob: %v", err)
	}

	return &info, nil
}

// Guess layers in base image (call base layers).
//
// e.g. In the following example, we should detect layers in debian:8.
//
//	FROM debian:8
//	RUN apt-get update
//	COPY mysecret /
//	ENTRYPOINT ["entrypoint.sh"]
//	CMD ["somecmd"]
//
// debian:8 may be like
//
//	ADD file:5d673d25da3a14ce1f6cf66e4c7fd4f4b85a3759a9d93efb3fd9ff852b5b56e4 in /
//	CMD ["/bin/sh"]
//
// In total, it would be like:
//
//	ADD file:5d673d25da3a14ce1f6cf66e4c7fd4f4b85a3759a9d93efb3fd9ff852b5b56e4 in /
//	CMD ["/bin/sh"]              # empty layer (detected)
//	RUN apt-get update
//	COPY mysecret /
//	ENTRYPOINT ["entrypoint.sh"] # empty layer (skipped)
//	CMD ["somecmd"]              # empty layer (skipped)
//
// This method tries to detect CMD in the second line and assume the first line is a base layer.
//  1. Iterate histories from the bottom.
//  2. Skip all the empty layers at the bottom. In the above example, "entrypoint.sh" and "somecmd" will be skipped
//  3. If it finds CMD, it assumes that it is the end of base layers.
//  4. It gets all the layers as base layers above the CMD found in #3.
func (a Artifact) guessBaseLayers(diffIDs []string, configFile *v1.ConfigFile) []string {
	if configFile == nil {
		return nil
	}

	var baseImageIndex int
	var foundNonEmpty bool
	for i := len(configFile.History) - 1; i >= 0; i-- {
		h := configFile.History[i]

		// Skip the last CMD, ENTRYPOINT, etc.
		if !foundNonEmpty {
			if h.EmptyLayer {
				continue
			}
			foundNonEmpty = true
		}

		if !h.EmptyLayer {
			continue
		}

		// Detect CMD instruction in base image
		if strings.HasPrefix(h.CreatedBy, "/bin/sh -c #(nop)  CMD") ||
			strings.HasPrefix(h.CreatedBy, "CMD") { // BuildKit
			baseImageIndex = i
			break
		}
	}

	// Diff IDs don't include empty layers, so the index is different from histories
	var diffIDIndex int
	var baseDiffIDs []string
	for i, h := range configFile.History {
		// It is no longer base layer.
		if i > baseImageIndex {
			break
		}
		// Empty layers are not included in diff IDs.
		if h.EmptyLayer {
			continue
		}

		if diffIDIndex >= len(diffIDs) {
			// something wrong...
			return nil
		}
		baseDiffIDs = append(baseDiffIDs, diffIDs[diffIDIndex])
		diffIDIndex++
	}
	return baseDiffIDs
}

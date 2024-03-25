package ebpftracer

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
)

func TestCgroupCleanupLoop(t *testing.T) {
	defer goleak.VerifyNone(t)
	r := require.New(t)

	tracer := buildTestTracer(withCgroupCleanupConfigured(100*time.Millisecond, 100*time.Millisecond))

	ctx, cancel := context.WithCancel(context.TODO())
	doneChan := make(chan struct{}, 1)

	go func() {
		tracer.cgroupCleanupLoop(ctx)
		doneChan <- struct{}{}
	}()

	tracer.queueCgroupForRemoval(10)
	tracer.queueCgroupForRemoval(20)
	tracer.queueCgroupForRemoval(30)

	r.Len(tracer.requestedCgroupCleanups, 3)

	r.Eventually(func() bool {
		tracer.cgroupCleanupMu.Lock()
		defer tracer.cgroupCleanupMu.Unlock()
		return len(tracer.requestedCgroupCleanups) == 0
	}, 5*time.Second, 100*time.Millisecond)

	cancel()

	select {
	case <-doneChan:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout reached!")
	}
}

func TestGetCgroupsToCleanup(t *testing.T) {
	type testCase struct {
		title           string
		now             time.Time
		cleanupRequests []cgroupCleanupRequest
	}

	now := time.Now()

	testCases := []testCase{
		{
			title: "requests before and after",
			now:   now,
			cleanupRequests: []cgroupCleanupRequest{
				{
					cgroupID:     10,
					cleanupAfter: now.Add(-10 * time.Second),
				},
				{
					cgroupID:     20,
					cleanupAfter: now.Add(10 * time.Second),
				},
				{
					cgroupID:     30,
					cleanupAfter: now.Add(15 * time.Second),
				},
			},
		},
		{
			title: "empty requests",
			now:   now,
		},
		{
			title: "only after",
			now:   now,
			cleanupRequests: []cgroupCleanupRequest{
				{
					cgroupID:     20,
					cleanupAfter: now.Add(10 * time.Second),
				},
				{
					cgroupID:     30,
					cleanupAfter: now.Add(15 * time.Second),
				},
			},
		},
		{
			title: "only before",
			now:   now,
			cleanupRequests: []cgroupCleanupRequest{
				{
					cgroupID:     20,
					cleanupAfter: now.Add(-10 * time.Second),
				},
				{
					cgroupID:     30,
					cleanupAfter: now.Add(-5 * time.Second),
				},
			},
		},
	}

	for _, test := range testCases {
		t.Run(test.title, func(t *testing.T) {
			r := require.New(t)

			toCleanup, future := splitCleanupRequests(test.now, test.cleanupRequests)

			for _, req := range toCleanup {
				r.True(req.cleanupAfter.Before(test.now))
			}
			for _, req := range future {
				r.False(req.cleanupAfter.Before(test.now))
			}
		})
	}

}

func withCgroupCleanupConfigured(cleanupTickRate time.Duration, cleanupDelay time.Duration) tracerOption {
	return func(t *Tracer) {
		t.cleanupTimerTickRate = cleanupTickRate
		t.cgroupCleanupDelay = cleanupDelay
	}
}

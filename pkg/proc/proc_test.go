package proc

import (
	"fmt"
	"strings"
	"syscall"
	"testing"
	"testing/fstest"
	"time"

	"github.com/stretchr/testify/require"
)

func TestLoadMountNSOldestProcesses(t *testing.T) {
	t.Run("should return process if only one in namespace", func(t *testing.T) {
		r := require.New(t)

		wantedPID := PID(12)
		wantedMountNSID := NamespaceID(10)

		procFS := fstest.MapFS{}
		procFS[fmt.Sprintf("%d/stat", wantedPID)] = buildStatMapFile()
		procFS[fmt.Sprintf("%d/ns/mnt", wantedPID)] = buildNamespaceMapFile(wantedMountNSID)

		procFS["99/stat"] = buildStatMapFile(StatFileStartTime(99))
		procFS["99/ns/mnt"] = buildNamespaceMapFile(99)

		proc := Proc{procFS: procFS}

		result, err := proc.LoadMountNSOldestProcesses()
		if err != nil {
			r.NoError(err)
		}

		r.Equal(wantedPID, result[wantedMountNSID])
	})

	t.Run("should return oldest process if multiple in namespace", func(t *testing.T) {
		r := require.New(t)

		oldestPID := PID(12)

		mountNSID := NamespaceID(10)

		procFS := fstest.MapFS{}
		procFS[fmt.Sprintf("%d/stat", oldestPID)] = buildStatMapFile()
		procFS[fmt.Sprintf("%d/ns/mnt", oldestPID)] = buildNamespaceMapFile(mountNSID)

		procFS["99/stat"] = buildStatMapFile(StatFileStartTime(99))
		procFS["99/ns/mnt"] = buildNamespaceMapFile(mountNSID)

		proc := Proc{procFS: procFS}

		result, err := proc.LoadMountNSOldestProcesses()
		if err != nil {
			r.NoError(err)
		}

		r.Equal(oldestPID, result[mountNSID])
	})

	t.Run("should not error if namespaces does not exist for one process", func(t *testing.T) {
		r := require.New(t)

		wantedPID := PID(12)
		wantedNSID := NamespaceID(10)

		procFS := fstest.MapFS{}
		procFS[fmt.Sprintf("%d/stat", wantedPID)] = buildStatMapFile()
		procFS[fmt.Sprintf("%d/ns/mnt", wantedPID)] = buildNamespaceMapFile(wantedNSID)

		procFS["99/stat"] = buildStatMapFile(StatFileStartTime(99))

		proc := Proc{procFS: procFS}

		result, err := proc.LoadMountNSOldestProcesses()
		if err != nil {
			r.NoError(err)
		}

		r.Equal(wantedPID, result[wantedNSID])
	})
}

type StatFileComm string
type StatFileParentPID PID
type StatFileStartTime uint64

func getOr[T any](or T, opts ...any) T {
	for _, v := range opts {
		if r, ok := v.(T); ok {
			return r
		}
	}

	return or
}

func buildStatMapFile(opts ...any) *fstest.MapFile {
	comm := getOr[StatFileComm]("systemd", opts...)
	ppid := getOr[StatFileParentPID](0, opts...)
	startTime := getOr[StatFileStartTime](0, opts...)

	return &fstest.MapFile{
		Data: []byte(fmt.Sprintf(strings.Join([]string{
			"1 (%s) S %d 1 1 0 -1 4194560 49750 11902233 171 14858 475 453",
			"49354 59480 20 0 1 0 %d 172085248 2208 18446744073709551615 1",
			"1 0 0 0 0 671173123 4096 1260 0 0 0 17 3 0 0 0 0 0 0 0 0 0 0 0 0 0",
		}, " "), comm, ppid, startTime)),
		Mode:    0666,
		ModTime: time.Now(),
	}
}

func buildNamespaceMapFile(id NamespaceID) *fstest.MapFile {
	return &fstest.MapFile{
		Data:    []byte{},
		Mode:    0666,
		ModTime: time.Now(),
		Sys: &syscall.Stat_t{
			Ino: uint64(id),
		},
	}
}

func TestGetNSForPID(t *testing.T) {
	type testCase struct {
		title           string
		namespaces      map[NamespaceType]uint64
		wantedNamespace NamespaceType
		expectedID      uint64
		expectError     bool
	}

	pidNSID := uint64(20)
	mntNSID := uint64(90)

	testCases := []testCase{
		{
			title: "should return requested namespace id",
			namespaces: map[NamespaceType]uint64{
				MountNamespace: mntNSID,
				PIDNamespace:   pidNSID,
			},
			wantedNamespace: MountNamespace,
			expectedID:      mntNSID,
		},
		{
			title: "should fail when requesting unknown namespace type",
			namespaces: map[NamespaceType]uint64{
				MountNamespace: mntNSID,
				PIDNamespace:   pidNSID,
			},
			wantedNamespace: "non existing",
			expectError:     true,
		},
	}
	testPID := PID(22)

	for _, test := range testCases {
		t.Run(test.title, func(t *testing.T) {
			r := require.New(t)

			procFS := buildTestNSProcFS(testPID, test.namespaces)
			proc := Proc{procFS: procFS}

			result, err := proc.GetNSForPID(testPID, test.wantedNamespace)
			if test.expectError {
				r.Error(err)
				return
			} else {
				r.NoError(err)
			}

			r.Equal(test.expectedID, result)
		})
	}
}

func buildTestNSProcFS(pid PID, namespaces map[NamespaceType]uint64) ProcFS {
	if namespaces == nil {
		return fstest.MapFS{}
	}

	result := fstest.MapFS{}

	for namespace, id := range namespaces {
		result[fmt.Sprintf("%d/ns/%s", pid, namespace)] = &fstest.MapFile{
			Data:    []byte{},
			Mode:    0666,
			ModTime: time.Now(),
			Sys: &syscall.Stat_t{
				Ino: id,
			},
		}
	}

	return result
}

func TestGetProcessStartTime(t *testing.T) {
	type testCase struct {
		title             string
		statFileData      []byte
		expectedStartTime uint64
		expectError       bool
	}

	testCases := []testCase{
		{
			title:             "parse simple stat file",
			statFileData:      []byte("1 (systemd) S 0 1 1 0 -1 4194560 49750 11902233 171 14858 475 453 49354 59480 20 0 1 0 0 172085248 2208 18446744073709551615 1 1 0 0 0 0 671173123 4096 1260 0 0 0 17 3 0 0 0 0 0 0 0 0 0 0 0 0 0"),
			expectedStartTime: 0,
		},
		{
			title:             "parse simple stat file with start time",
			statFileData:      []byte("1 (bash) S 0 1 1 0 -1 4194560 49750 11902233 171 14858 475 453 49354 59480 20 0 1 0 20 172085248 2208 18446744073709551615 1 1 0 0 0 0 671173123 4096 1260 0 0 0 17 3 0 0 0 0 0 0 0 0 0 0 0 0 0"),
			expectedStartTime: 20,
		},
		{
			title:             "parse simple stat file with space in comm",
			statFileData:      []byte("1 (bash 1) S 0 1 1 0 -1 4194560 49750 11902233 171 14858 475 453 49354 59480 20 0 1 0 20 172085248 2208 18446744073709551615 1 1 0 0 0 0 671173123 4096 1260 0 0 0 17 3 0 0 0 0 0 0 0 0 0 0 0 0 0"),
			expectedStartTime: 20,
		},
		{
			title:             "parse simple stat file with extremely long runtime",
			statFileData:      []byte("1 (bash 1) S 0 1 1 0 -1 4194560 49750 11902233 171 14858 475 453 49354 59480 20 0 1 0 99999999 172085248 2208 18446744073709551615 1 1 0 0 0 0 671173123 4096 1260 0 0 0 17 3 0 0 0 0 0 0 0 0 0 0 0 0 0"),
			expectedStartTime: 99999999,
		},
		{
			title:       "should fail with error if stat file is missing",
			expectError: true,
		},
		{
			title:        "should fail with error if stat file does not have enough fields",
			statFileData: []byte("1 (bash 1) S 0 1 1 0 "),
			expectError:  true,
		},
	}
	testPID := PID(22)

	for _, test := range testCases {
		t.Run(test.title, func(t *testing.T) {
			r := require.New(t)

			procFS := buildTestProcStatFileFS(testPID, test.statFileData)
			proc := Proc{procFS: procFS}

			result, err := proc.GetProcessStartTime(testPID)
			if test.expectError {
				r.Error(err)
				return
			} else {
				r.NoError(err)
			}

			r.Equal(test.expectedStartTime, result)
		})
	}
}

func buildTestProcStatFileFS(pid PID, statFileData []byte) ProcFS {
	if statFileData == nil {
		return fstest.MapFS{}
	}

	return fstest.MapFS{
		fmt.Sprintf("%d/stat", pid): &fstest.MapFile{
			Data:    statFileData,
			Mode:    0666,
			ModTime: time.Now(),
		},
	}
}

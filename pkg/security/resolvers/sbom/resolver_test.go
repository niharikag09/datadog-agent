// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux

package sbom

import (
	"testing"

	"github.com/hashicorp/golang-lru/v2/simplelru"

	sbomtypes "github.com/DataDog/datadog-agent/pkg/security/resolvers/sbom/types"
	"github.com/DataDog/datadog-agent/pkg/security/secl/containerutils"
	"github.com/DataDog/datadog-agent/pkg/security/utils/cache"
)

// TestRefreshScanResetsStateForRescan checks that refreshing a workload clears
// its cached SBOM data, resets the SBOM to the pending state, and re-queues it
// for a scan. The state reset matters because analyzeWorkload drops any SBOM
// not in the pending state: a workload is left computed by its initial scan, so
// without the reset the refresh re-scan is silently discarded and the runtime
// properties are never recomputed.
func TestRefreshScanResetsStateForRescan(t *testing.T) {
	dataCache, err := simplelru.NewLRU[workloadKey, *Data](10, nil)
	if err != nil {
		t.Fatalf("NewLRU: %v", err)
	}
	r := &Resolver{
		dataCache: dataCache,
		scanChan:  make(chan *SBOM, 10),
	}

	sbom := NewSBOM("container-id", nil, "image:tag")
	sbom.state.Store(computedState)
	dataCache.Add("image:tag", &Data{})

	r.refreshScan(sbom)

	if got := sbom.state.Load(); got != pendingState {
		t.Errorf("state = %d, want pendingState (%d)", got, pendingState)
	}
	if _, ok := dataCache.Get("image:tag"); ok {
		t.Errorf("cached SBOM data was not invalidated")
	}
	select {
	case queued := <-r.scanChan:
		if queued != sbom {
			t.Errorf("queued unexpected SBOM for re-scan")
		}
	default:
		t.Errorf("workload was not re-queued for a scan")
	}
}

func newPendingFilesResolver(t *testing.T, size int) *Resolver {
	pendingFiles, err := cache.NewTwoLayersLRU[containerutils.ContainerID, string, pendingFileAccess](size)
	if err != nil {
		t.Fatalf("NewTwoLayersLRU: %v", err)
	}
	return &Resolver{pendingFiles: pendingFiles}
}

// TestPendingFileAccessesAreDeduplicatedPerPath checks that repeated accesses to the
// same file collapse into a single entry with the sticky properties merged. The
// snapshot replay emits one open event per (process, mapped file) pair and runs again
// on every ruleset reload, so the shared libraries mapped by every process of a
// workload would otherwise evict the distinct paths worth keeping.
func TestPendingFileAccessesAreDeduplicatedPerPath(t *testing.T) {
	r := newPendingFilesResolver(t, maxPendingFileAccesses)

	for range 3 {
		r.queuePendingFileAccess("container-id", "/usr/lib/libc.so.6", 0644, 1000)
	}
	r.queuePendingFileAccess("container-id", "/usr/bin/su", 04755, 1000)
	r.queuePendingFileAccess("container-id", "/usr/bin/su", 0755, 0)

	if got := r.pendingFiles.Len(); got != 2 {
		t.Fatalf("queued %d distinct accesses, want 2", got)
	}
	if access, _ := r.pendingFiles.Get("container-id", "/usr/lib/libc.so.6"); access.suidBit || access.accessedByRoot {
		t.Errorf("libc access = %+v, want no sticky property set", access)
	}
	if access, _ := r.pendingFiles.Get("container-id", "/usr/bin/su"); !access.suidBit || !access.accessedByRoot {
		t.Errorf("su access = %+v, want both sticky properties merged", access)
	}
}

// TestPendingFileAccessesEvictTheOldestPastTheBound checks that the accesses are
// bounded across all containers, dropping the least recently accessed path.
func TestPendingFileAccessesEvictTheOldestPastTheBound(t *testing.T) {
	r := newPendingFilesResolver(t, 2)

	r.queuePendingFileAccess("container-id", "/usr/lib/libc.so.6", 0644, 1000)
	r.queuePendingFileAccess("other-container-id", "/usr/bin/su", 04755, 0)
	r.queuePendingFileAccess("other-container-id", "/usr/lib/libssl.so.3", 0644, 1000)

	if got := r.pendingFiles.Len(); got != 2 {
		t.Fatalf("queued %d accesses, want 2", got)
	}
	if _, ok := r.pendingFiles.Get("container-id", "/usr/lib/libc.so.6"); ok {
		t.Errorf("the least recently accessed path was not evicted")
	}
	if _, ok := r.pendingFiles.Get("other-container-id", "/usr/lib/libssl.so.3"); !ok {
		t.Errorf("the most recently accessed path was not kept")
	}
}

// TestProcessPendingFileAccessesEnrichesPackages checks that draining the pending
// accesses applies them to the packages owning the files and marks the SBOM for
// forwarding.
func TestProcessPendingFileAccessesEnrichesPackages(t *testing.T) {
	r := newPendingFilesResolver(t, maxPendingFileAccesses)

	sbom := NewSBOM("container-id", nil, "image:tag")
	sbom.data = newData([]sbomtypes.PackageWithInstalledFiles{{
		Package:        sbomtypes.Package{Name: "shadow-utils"},
		InstalledFiles: []string{"/usr/bin/su"},
	}}, false)

	r.queuePendingFileAccess("container-id", "/usr/bin/su", 04755, 0)
	r.queuePendingFileAccess("container-id", "/usr/bin/not-in-any-package", 0644, 1000)

	r.processPendingFileAccesses(sbom)

	if r.pendingFiles.Len() != 0 {
		t.Errorf("pending accesses were not drained")
	}
	if pkg := sbom.data.packages[0]; pkg.LastAccess.IsZero() || !pkg.SuidBit || !pkg.AccessedByRoot {
		t.Errorf("package = %+v, want last access and both sticky properties set", pkg)
	}
	if !sbom.invalidated {
		t.Errorf("sbom was not marked for forwarding")
	}
}

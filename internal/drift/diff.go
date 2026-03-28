package drift

import (
	"reflect"

	"github.com/jgiornazi/meshaudit/internal/k8s"
)

// DriftStatus describes the relationship between a live VS and its desired state.
type DriftStatus string

const (
	// StatusInSync means live and desired specs are identical.
	StatusInSync DriftStatus = "IN_SYNC"
	// StatusDrifted means both live and desired exist but their specs differ.
	StatusDrifted DriftStatus = "DRIFT_DETECTED"
	// StatusLiveOnly means the VS exists in the cluster but not in the manifest directory.
	StatusLiveOnly DriftStatus = "LIVE_ONLY"
	// StatusManifestOnly means the VS exists in the manifest directory but is not deployed.
	StatusManifestOnly DriftStatus = "MANIFEST_ONLY"
)

// FieldDiff records a single spec key where live and desired values diverge.
type FieldDiff struct {
	Field   string      `json:"field"`
	Live    interface{} `json:"live"`
	Desired interface{} `json:"desired"`
}

// VSResult is the drift result for one VirtualService.
type VSResult struct {
	Name      string      `json:"name"`
	Namespace string      `json:"namespace"`
	Status    DriftStatus `json:"status"`
	// Diffs is populated only when Status is DRIFT_DETECTED.
	Diffs []FieldDiff `json:"diffs,omitempty"`
}

// Compare matches live VirtualService resources against desired manifests by
// namespace+name and returns one VSResult per unique VS seen in either source.
func Compare(live, desired []k8s.VirtualService) []VSResult {
	// Index desired by namespace/name for O(1) lookup.
	desiredIdx := make(map[string]k8s.VirtualService, len(desired))
	for _, d := range desired {
		desiredIdx[vsKey(d)] = d
	}

	// Index live for MANIFEST_ONLY detection.
	liveIdx := make(map[string]k8s.VirtualService, len(live))
	for _, l := range live {
		liveIdx[vsKey(l)] = l
	}

	var results []VSResult

	// Walk live resources first.
	for _, l := range live {
		key := vsKey(l)
		d, found := desiredIdx[key]
		if !found {
			results = append(results, VSResult{
				Name:      l.Name,
				Namespace: l.Namespace,
				Status:    StatusLiveOnly,
			})
			continue
		}

		diffs := diffSpecs(l.Spec, d.Spec)
		if len(diffs) == 0 {
			results = append(results, VSResult{
				Name:      l.Name,
				Namespace: l.Namespace,
				Status:    StatusInSync,
			})
		} else {
			results = append(results, VSResult{
				Name:      l.Name,
				Namespace: l.Namespace,
				Status:    StatusDrifted,
				Diffs:     diffs,
			})
		}
	}

	// Walk desired resources to find MANIFEST_ONLY entries.
	for _, d := range desired {
		if _, found := liveIdx[vsKey(d)]; !found {
			results = append(results, VSResult{
				Name:      d.Name,
				Namespace: d.Namespace,
				Status:    StatusManifestOnly,
			})
		}
	}

	return results
}

// vsKey returns a stable namespace/name lookup key for a VirtualService.
func vsKey(vs k8s.VirtualService) string {
	return vs.Namespace + "/" + vs.Name
}

// diffSpecs compares two spec maps and returns a FieldDiff for each top-level
// key where the values differ. Both maps are compared with reflect.DeepEqual.
func diffSpecs(live, desired map[string]interface{}) []FieldDiff {
	var diffs []FieldDiff

	// Keys present in live.
	seen := make(map[string]bool)
	for k, lv := range live {
		seen[k] = true
		dv := desired[k]
		if !reflect.DeepEqual(lv, dv) {
			diffs = append(diffs, FieldDiff{
				Field:   "spec." + k,
				Live:    lv,
				Desired: dv,
			})
		}
	}

	// Keys only in desired (live value is nil/absent).
	for k, dv := range desired {
		if seen[k] {
			continue
		}
		diffs = append(diffs, FieldDiff{
			Field:   "spec." + k,
			Live:    nil,
			Desired: dv,
		})
	}

	return diffs
}

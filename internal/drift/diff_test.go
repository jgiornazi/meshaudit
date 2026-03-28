package drift

import (
	"testing"

	"github.com/jgiornazi/meshaudit/internal/k8s"
)

func vs(name, ns string, spec map[string]interface{}) k8s.VirtualService {
	return k8s.VirtualService{Name: name, Namespace: ns, Spec: spec}
}

func TestCompare_InSync(t *testing.T) {
	spec := map[string]interface{}{"hosts": []interface{}{"reviews"}}
	live := []k8s.VirtualService{vs("reviews-vs", "production", spec)}
	desired := []k8s.VirtualService{vs("reviews-vs", "production", spec)}

	results := Compare(live, desired)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Status != StatusInSync {
		t.Errorf("status = %q, want IN_SYNC", results[0].Status)
	}
	if len(results[0].Diffs) != 0 {
		t.Errorf("expected no diffs for in-sync VS, got %v", results[0].Diffs)
	}
}

func TestCompare_Drifted(t *testing.T) {
	liveSpec := map[string]interface{}{
		"hosts": []interface{}{"reviews"},
		"http":  []interface{}{map[string]interface{}{"timeout": "10s"}},
	}
	desiredSpec := map[string]interface{}{
		"hosts": []interface{}{"reviews"},
		"http":  []interface{}{map[string]interface{}{"timeout": "5s"}},
	}
	live := []k8s.VirtualService{vs("reviews-vs", "production", liveSpec)}
	desired := []k8s.VirtualService{vs("reviews-vs", "production", desiredSpec)}

	results := Compare(live, desired)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Status != StatusDrifted {
		t.Errorf("status = %q, want DRIFT_DETECTED", results[0].Status)
	}
	if len(results[0].Diffs) == 0 {
		t.Error("expected diffs, got none")
	}
	if results[0].Diffs[0].Field != "spec.http" {
		t.Errorf("diff field = %q, want spec.http", results[0].Diffs[0].Field)
	}
}

func TestCompare_LiveOnly(t *testing.T) {
	live := []k8s.VirtualService{vs("reviews-vs", "production", map[string]interface{}{})}
	desired := []k8s.VirtualService{}

	results := Compare(live, desired)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Status != StatusLiveOnly {
		t.Errorf("status = %q, want LIVE_ONLY", results[0].Status)
	}
}

func TestCompare_ManifestOnly(t *testing.T) {
	live := []k8s.VirtualService{}
	desired := []k8s.VirtualService{vs("new-vs", "staging", map[string]interface{}{})}

	results := Compare(live, desired)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Status != StatusManifestOnly {
		t.Errorf("status = %q, want MANIFEST_ONLY", results[0].Status)
	}
	if results[0].Name != "new-vs" {
		t.Errorf("name = %q, want new-vs", results[0].Name)
	}
}

func TestCompare_MultiNamespace(t *testing.T) {
	live := []k8s.VirtualService{
		vs("vs-a", "production", map[string]interface{}{"hosts": []interface{}{"a"}}),
		vs("vs-b", "staging", map[string]interface{}{"hosts": []interface{}{"b"}}),
	}
	desired := []k8s.VirtualService{
		vs("vs-a", "production", map[string]interface{}{"hosts": []interface{}{"a"}}),
		vs("vs-b", "staging", map[string]interface{}{"hosts": []interface{}{"b-changed"}}),
	}

	results := Compare(live, desired)
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	statusMap := map[string]DriftStatus{}
	for _, r := range results {
		statusMap[r.Namespace+"/"+r.Name] = r.Status
	}
	if statusMap["production/vs-a"] != StatusInSync {
		t.Errorf("production/vs-a: status = %q, want IN_SYNC", statusMap["production/vs-a"])
	}
	if statusMap["staging/vs-b"] != StatusDrifted {
		t.Errorf("staging/vs-b: status = %q, want DRIFT_DETECTED", statusMap["staging/vs-b"])
	}
}

func TestCompare_SameNameDifferentNamespace(t *testing.T) {
	// Two VSes with the same name in different namespaces should be treated independently.
	live := []k8s.VirtualService{
		vs("reviews-vs", "production", map[string]interface{}{"hosts": []interface{}{"prod"}}),
		vs("reviews-vs", "staging", map[string]interface{}{"hosts": []interface{}{"staging"}}),
	}
	desired := []k8s.VirtualService{
		vs("reviews-vs", "production", map[string]interface{}{"hosts": []interface{}{"prod"}}),
		// staging VS is not in desired — should be LIVE_ONLY.
	}

	results := Compare(live, desired)
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	statusMap := map[string]DriftStatus{}
	for _, r := range results {
		statusMap[r.Namespace+"/"+r.Name] = r.Status
	}
	if statusMap["production/reviews-vs"] != StatusInSync {
		t.Errorf("production/reviews-vs: got %q, want IN_SYNC", statusMap["production/reviews-vs"])
	}
	if statusMap["staging/reviews-vs"] != StatusLiveOnly {
		t.Errorf("staging/reviews-vs: got %q, want LIVE_ONLY", statusMap["staging/reviews-vs"])
	}
}

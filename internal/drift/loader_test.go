package drift

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadManifests_DirNotFound(t *testing.T) {
	_, err := LoadManifests("/nonexistent/path/that/does/not/exist", "")
	if err == nil {
		t.Error("expected error for nonexistent directory, got nil")
	}
}

func TestLoadManifests_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	vses, err := LoadManifests(dir, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(vses) != 0 {
		t.Errorf("expected 0 VSes, got %d", len(vses))
	}
}

func TestLoadManifests_SkipsNonVS(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "service.yaml", `
apiVersion: v1
kind: Service
metadata:
  name: frontend
  namespace: production
`)
	vses, err := LoadManifests(dir, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(vses) != 0 {
		t.Errorf("expected 0 VSes (Service should be skipped), got %d", len(vses))
	}
}

func TestLoadManifests_SingleVS(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "reviews-vs.yaml", `
apiVersion: networking.istio.io/v1beta1
kind: VirtualService
metadata:
  name: reviews-vs
  namespace: production
spec:
  hosts:
    - reviews
  http:
    - route:
        - destination:
            host: reviews
            subset: v1
`)
	vses, err := LoadManifests(dir, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(vses) != 1 {
		t.Fatalf("expected 1 VS, got %d", len(vses))
	}
	if vses[0].Name != "reviews-vs" {
		t.Errorf("Name = %q, want %q", vses[0].Name, "reviews-vs")
	}
	if vses[0].Namespace != "production" {
		t.Errorf("Namespace = %q, want %q", vses[0].Namespace, "production")
	}
}

func TestLoadManifests_MultiDoc(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "two-vses.yaml", `
apiVersion: networking.istio.io/v1beta1
kind: VirtualService
metadata:
  name: reviews-vs
  namespace: production
spec:
  hosts: [reviews]
---
apiVersion: networking.istio.io/v1beta1
kind: VirtualService
metadata:
  name: ratings-vs
  namespace: production
spec:
  hosts: [ratings]
`)
	vses, err := LoadManifests(dir, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(vses) != 2 {
		t.Fatalf("expected 2 VSes, got %d", len(vses))
	}
}

func TestLoadManifests_NamespaceFilter(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "vses.yaml", `
apiVersion: networking.istio.io/v1beta1
kind: VirtualService
metadata:
  name: prod-vs
  namespace: production
spec:
  hosts: [reviews]
---
apiVersion: networking.istio.io/v1beta1
kind: VirtualService
metadata:
  name: staging-vs
  namespace: staging
spec:
  hosts: [reviews]
`)
	vses, err := LoadManifests(dir, "production")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(vses) != 1 {
		t.Fatalf("expected 1 VS after namespace filter, got %d", len(vses))
	}
	if vses[0].Name != "prod-vs" {
		t.Errorf("expected prod-vs, got %q", vses[0].Name)
	}
}

func TestLoadManifests_SkipsHiddenDir(t *testing.T) {
	dir := t.TempDir()
	hiddenDir := filepath.Join(dir, ".git")
	if err := os.Mkdir(hiddenDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, hiddenDir, "vs.yaml", `
apiVersion: networking.istio.io/v1beta1
kind: VirtualService
metadata:
  name: hidden-vs
  namespace: production
spec:
  hosts: [reviews]
`)
	vses, err := LoadManifests(dir, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(vses) != 0 {
		t.Errorf("expected hidden dir to be skipped, got %d VSes", len(vses))
	}
}

func TestLoadManifests_SkipsNonYAML(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "README.md", "# some readme content")
	writeFile(t, dir, "script.sh", "#!/bin/bash\necho hello")
	vses, err := LoadManifests(dir, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(vses) != 0 {
		t.Errorf("expected non-YAML files to be skipped, got %d VSes", len(vses))
	}
}

// writeFile is a test helper that creates a file with the given content.
func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %q: %v", path, err)
	}
}

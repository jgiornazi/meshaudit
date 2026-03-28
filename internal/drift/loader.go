package drift

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"sigs.k8s.io/yaml"

	"github.com/jgiornazi/meshaudit/internal/k8s"
)

// LoadManifests walks dir recursively, parses all YAML/JSON files, and returns
// every object whose apiVersion is "networking.istio.io/v1beta1" (or v1alpha3)
// and kind is "VirtualService". Non-VS objects and hidden directories are
// silently skipped.
//
// If namespace is non-empty only manifests whose metadata.namespace matches are
// returned (supports --namespace scoping for monorepo layouts).
func LoadManifests(dir, namespace string) ([]k8s.VirtualService, error) {
	if _, err := os.Stat(dir); err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("git-path %q does not exist", dir)
		}
		return nil, fmt.Errorf("stat %q: %w", dir, err)
	}

	var vsList []k8s.VirtualService

	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// Skip hidden directories (e.g. .git, .github).
		if d.IsDir() && strings.HasPrefix(d.Name(), ".") {
			return filepath.SkipDir
		}

		if d.IsDir() {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" && ext != ".json" {
			return nil
		}

		f, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("open %q: %w", path, err)
		}
		defer f.Close()

		data, err := io.ReadAll(f)
		if err != nil {
			return fmt.Errorf("read %q: %w", path, err)
		}

		vses, err := parseVirtualServices(data, namespace)
		if err != nil {
			// Skip unparseable files rather than aborting the walk.
			return nil
		}
		vsList = append(vsList, vses...)
		return nil
	})

	return vsList, err
}

// parseVirtualServices parses one or more YAML documents from data and returns
// any that are Istio VirtualService resources. Documents are separated by "---".
func parseVirtualServices(data []byte, namespace string) ([]k8s.VirtualService, error) {
	var vsList []k8s.VirtualService

	// Split on YAML document separator.
	docs := splitYAMLDocs(data)
	for _, doc := range docs {
		doc = strings.TrimSpace(doc)
		if doc == "" || doc == "---" {
			continue
		}

		var obj map[string]interface{}
		if err := yaml.Unmarshal([]byte(doc), &obj); err != nil {
			continue
		}
		if obj == nil {
			continue
		}

		if !isVirtualService(obj) {
			continue
		}

		name, ns := metaFields(obj)
		if name == "" {
			continue
		}
		if namespace != "" && ns != namespace {
			continue
		}

		spec, _ := obj["spec"].(map[string]interface{})
		if spec == nil {
			spec = map[string]interface{}{}
		}

		vsList = append(vsList, k8s.VirtualService{
			Name:      name,
			Namespace: ns,
			Spec:      spec,
		})
	}
	return vsList, nil
}

// isVirtualService returns true when the object's apiVersion and kind identify
// it as an Istio VirtualService.
func isVirtualService(obj map[string]interface{}) bool {
	kind, _ := obj["kind"].(string)
	if kind != "VirtualService" {
		return false
	}
	apiVersion, _ := obj["apiVersion"].(string)
	return strings.HasPrefix(apiVersion, "networking.istio.io/")
}

// metaFields extracts name and namespace from metadata.
func metaFields(obj map[string]interface{}) (name, namespace string) {
	meta, _ := obj["metadata"].(map[string]interface{})
	if meta == nil {
		return "", ""
	}
	name, _ = meta["name"].(string)
	namespace, _ = meta["namespace"].(string)
	return name, namespace
}

// splitYAMLDocs splits a YAML byte slice on "---" document separators.
func splitYAMLDocs(data []byte) []string {
	return strings.Split(string(data), "\n---")
}

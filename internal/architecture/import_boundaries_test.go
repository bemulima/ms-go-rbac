package architecture_test

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const modulePath = "github.com/example/ms-rbac-service/"

func TestInwardPackagesDoNotImportTransportOrInfrastructure(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	rules := map[string][]string{
		"internal/domain":  {modulePath + "internal/transport", modulePath + "internal/infrastructure"},
		"internal/usecase": {modulePath + "internal/transport", modulePath + "internal/infrastructure"},
	}
	for relativeDir, forbidden := range rules {
		dir := filepath.Join(root, relativeDir)
		err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() || !strings.HasSuffix(path, ".go") {
				return nil
			}
			file, parseErr := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
			if parseErr != nil {
				return parseErr
			}
			for _, imported := range file.Imports {
				importPath, unquoteErr := strconv.Unquote(imported.Path.Value)
				if unquoteErr != nil {
					return unquoteErr
				}
				for _, prefix := range forbidden {
					if importPath == prefix || strings.HasPrefix(importPath, prefix+"/") {
						t.Errorf("%s imports forbidden package %s", path, importPath)
					}
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("scan %s: %v", relativeDir, err)
		}
	}
}

func TestTransportContoursUseTheApprovedLayout(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	assertDirectDirectories(t, filepath.Join(root, "internal", "transport"), map[string]bool{"http": true, "message": true})
	assertDirectDirectories(t, filepath.Join(root, "internal", "transport", "http"), map[string]bool{"api": true, "admin": true, "private": true, "common": true})
	if _, err := os.Stat(filepath.Join(root, "internal", "adapters")); !os.IsNotExist(err) {
		t.Error("internal/adapters must not exist")
	}
}

func assertDirectDirectories(t *testing.T, path string, allowed map[string]bool) {
	t.Helper()
	entries, err := os.ReadDir(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() && !allowed[entry.Name()] {
			t.Errorf("unexpected directory %s", filepath.Join(path, entry.Name()))
		}
	}
	for name := range allowed {
		if _, err := os.Stat(filepath.Join(path, name)); err != nil {
			t.Errorf("required directory %s is missing", filepath.Join(path, name))
		}
	}
}

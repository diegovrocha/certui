package ui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFilePickerFilter(t *testing.T) {
	fp := FilePicker{
		entries: []fileEntry{
			{name: "cert.pem", isDir: false},
			{name: "key.pem", isDir: false},
			{name: "rv2.pfx", isDir: false},
			{name: "cert_chain.pem", isDir: false},
			{name: "server.crt", isDir: false},
		},
		filtered: []fileEntry{
			{name: "cert.pem"},
			{name: "key.pem"},
			{name: "rv2.pfx"},
			{name: "cert_chain.pem"},
			{name: "server.crt"},
		},
	}

	// Filter by "rv2"
	query := "rv2"
	fp.filtered = nil
	for _, e := range fp.entries {
		if strings.Contains(strings.ToLower(e.name), query) {
			fp.filtered = append(fp.filtered, e)
		}
	}

	if len(fp.filtered) != 1 {
		t.Errorf("Filter 'rv2' should return 1 file, returned %d", len(fp.filtered))
	}
	if fp.filtered[0].name != "rv2.pfx" {
		t.Errorf("Filter 'rv2' should return 'rv2.pfx', returned '%s'", fp.filtered[0].name)
	}

	// Filter by "pem"
	query = "pem"
	fp.filtered = nil
	for _, e := range fp.entries {
		if strings.Contains(strings.ToLower(e.name), query) {
			fp.filtered = append(fp.filtered, e)
		}
	}

	if len(fp.filtered) != 3 {
		t.Errorf("Filter 'pem' should return 3 files, returned %d", len(fp.filtered))
	}

	// Empty filter returns all
	fp.filtered = fp.entries
	if len(fp.filtered) != 5 {
		t.Errorf("No filter should return 5 files, returned %d", len(fp.filtered))
	}
}

func TestFilePickerCursorBounds(t *testing.T) {
	fp := FilePicker{
		entries:  []fileEntry{{name: "a.pem"}, {name: "b.pem"}, {name: "c.pem"}},
		filtered: []fileEntry{{name: "a.pem"}, {name: "b.pem"}, {name: "c.pem"}},
		cursor:   0,
	}

	if fp.cursor < 0 {
		t.Error("Cursor should not be negative")
	}

	fp.cursor = len(fp.filtered) - 1
	if fp.cursor >= len(fp.filtered) {
		t.Error("Cursor should not exceed list size")
	}
}

func TestFilePickerView(t *testing.T) {
	fp := FilePicker{
		Prompt:   "Select file",
		cwd:      "/tmp",
		entries:  []fileEntry{{name: "test.pem", isDir: false}},
		filtered: []fileEntry{{name: "test.pem", isDir: false}},
		cursor:   0,
	}
	fp.filter.Placeholder = "type to filter..."

	v := fp.View()
	if !strings.Contains(v, "Select file") {
		t.Error("View should contain the prompt")
	}
	if !strings.Contains(v, "test.pem") {
		t.Error("View should contain the file")
	}
}

func TestFilePickerEmpty(t *testing.T) {
	fp := FilePicker{
		Prompt:   "Select",
		cwd:      "/tmp",
		entries:  []fileEntry{},
		filtered: []fileEntry{},
	}
	fp.filter.Placeholder = "type to filter..."

	v := fp.View()
	if !strings.Contains(v, "No files found") {
		t.Error("Empty view should show no files found message")
	}
}

func TestFilePickerDirNavigation(t *testing.T) {
	dir := t.TempDir()
	subdir := filepath.Join(dir, "certs")
	os.Mkdir(subdir, 0755)
	os.WriteFile(filepath.Join(subdir, "test.pem"), []byte("cert"), 0644)

	fp := newPicker("Select", []string{".pem"})
	fp.cwd = dir
	fp.loadDir()

	// Should show the subdir
	found := false
	for _, e := range fp.entries {
		if e.isDir && e.name == "certs/" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Should list subdirectory 'certs/'")
	}

	// Navigate into subdir
	for i, e := range fp.entries {
		if e.isDir && e.name == "certs/" {
			fp.cursor = i
			break
		}
	}
	fp.cwd = fp.entries[fp.cursor].path
	fp.loadDir()

	// Should show the file
	foundFile := false
	for _, e := range fp.entries {
		if !e.isDir && e.name == "test.pem" {
			foundFile = true
			break
		}
	}
	if !foundFile {
		t.Error("Should list 'test.pem' inside subdir")
	}
}

func TestFilePickerShowsAllDirs(t *testing.T) {
	// Show all directories so the user can navigate freely; certs may live
	// deeper than the previous 2-level scan would catch.
	dir := t.TempDir()
	os.Mkdir(filepath.Join(dir, "empty"), 0755)
	os.Mkdir(filepath.Join(dir, "hascert"), 0755)
	os.WriteFile(filepath.Join(dir, "hascert", "cert.pem"), []byte("cert"), 0644)

	fp := newPicker("Select", []string{".pem"})
	fp.cwd = dir
	fp.loadDir()

	var foundEmpty, foundHasCert bool
	for _, e := range fp.entries {
		if e.isDir && e.name == "empty/" {
			foundEmpty = true
		}
		if e.isDir && e.name == "hascert/" {
			foundHasCert = true
		}
	}
	if !foundEmpty {
		t.Error("empty directory should be listed for free navigation")
	}
	if !foundHasCert {
		t.Error("directory with matching files should be listed")
	}
}

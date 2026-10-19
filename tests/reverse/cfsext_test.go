package reverse_test

import (
	"bytes"
	"errors"
	"os"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/rfjakob/gocryptfs/v2/ctlsock"
	"github.com/rfjakob/gocryptfs/v2/tests/test_helpers"
)

// readdirNames returns the sorted names of the entries in "dir".
func readdirNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

// TestCfsExtView checks that with -cfsext, non-directories show up in the
// encrypted view (dirB) as NAME.cfs while directories keep their name, and
// that the forward mount (dirC) maps everything back.
func TestCfsExtView(t *testing.T) {
	if !cfsext {
		t.Skip("only for -cfsext")
	}
	wd := t.Name()
	pWd := dirA + "/" + wd
	if err := os.MkdirAll(pWd+"/d", 0700); err != nil {
		t.Fatal(err)
	}
	content := []byte("hello cfsext")
	if err := os.WriteFile(pWd+"/f", content, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pWd+"/d/g", nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("f", pWd+"/l"); err != nil {
		t.Fatal(err)
	}

	// Encrypted view
	cWd := dirB + "/" + wd
	if names := readdirNames(t, cWd); !slices.Equal(names, []string{"d", "f.cfs", "l.cfs"}) {
		t.Errorf("wrong listing of %q: %q", cWd, names)
	}
	if fi, err := os.Lstat(cWd + "/f.cfs"); err != nil || !fi.Mode().IsRegular() {
		t.Errorf("f.cfs should be a regular file: fi=%v err=%v", fi, err)
	}
	if _, err := os.Lstat(cWd + "/f"); !errors.Is(err, syscall.ENOENT) {
		t.Errorf("f: want ENOENT, got %v", err)
	}
	if fi, err := os.Lstat(cWd + "/d"); err != nil || !fi.IsDir() {
		t.Errorf("d should be a directory: fi=%v err=%v", fi, err)
	}
	if !test_helpers.VerifyExistence(t, cWd+"/d/g.cfs") {
		t.Errorf("d/g.cfs missing")
	}
	if fi, err := os.Lstat(cWd + "/l.cfs"); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Errorf("l.cfs should be a symlink: fi=%v err=%v", fi, err)
	}
	if target, err := os.Readlink(cWd + "/l.cfs"); err != nil || target != "f" {
		t.Errorf("l.cfs: want target \"f\", got %q, err=%v", target, err)
	}

	// Round trip through the forward mount
	pWdC := dirC + "/" + wd
	if names := readdirNames(t, pWdC); !slices.Equal(names, []string{"d", "f", "l"}) {
		t.Errorf("wrong listing of %q: %q", pWdC, names)
	}
	if data, err := os.ReadFile(pWdC + "/f"); err != nil || !bytes.Equal(data, content) {
		t.Errorf("f: want content %q, got %q, err=%v", content, data, err)
	}
	if !test_helpers.VerifyExistence(t, pWdC+"/d/g") {
		t.Errorf("d/g missing")
	}
	if target, err := os.Readlink(pWdC + "/l"); err != nil || target != "f" {
		t.Errorf("l: want target \"f\", got %q, err=%v", target, err)
	}

	// Control socket. newReverseFS puts it next to the mountpoint.
	sock := dirB + ".sock"
	for _, tc := range [][2]string{
		{wd + "/d", wd + "/d"},
		{wd + "/d/g", wd + "/d/g.cfs"},
		{wd + "/f", wd + "/f.cfs"},
	} {
		if have := ctlsockEncryptPath(t, sock, tc[0]); have != tc[1] {
			t.Errorf("EncryptPath(%q): want %q, have %q", tc[0], tc[1], have)
		}
		resp := test_helpers.QueryCtlSock(t, sock, ctlsock.RequestStruct{DecryptPath: tc[1]})
		if resp.ErrNo != 0 || resp.Result != tc[0] {
			t.Errorf("DecryptPath(%q): want %q, have %q, ErrNo=%d ErrText=%s", tc[1], tc[0], resp.Result, resp.ErrNo, resp.ErrText)
		}
	}
}

// TestCfsExtTooLong checks that a name that becomes longer than 255 bytes
// with the ".cfs" suffix is skipped in the encrypted view.
func TestCfsExtTooLong(t *testing.T) {
	if !cfsext {
		t.Skip("only for -cfsext")
	}
	// Skipping the long name logs a warning, so we need -wpanic=0
	backingDir, mnt, _ := newReverseFS([]string{"-wpanic=0"})
	defer func() {
		test_helpers.UnmountPanic(mnt)
		os.Remove(mnt)
		os.RemoveAll(backingDir)
	}()

	name251 := strings.Repeat("a", 251)
	name252 := strings.Repeat("b", 252)
	for _, n := range []string{name251, name252} {
		if err := os.WriteFile(backingDir+"/"+n, nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	names := readdirNames(t, mnt)
	if !slices.Contains(names, name251+".cfs") {
		t.Errorf("%d-byte name is missing from the listing: %q", len(name251), names)
	}
	for _, n := range names {
		if strings.HasPrefix(n, "b") {
			t.Errorf("%d-byte name should not be listed, but found %q", len(name252), n)
		}
	}
	if !test_helpers.VerifyExistence(t, mnt+"/"+name251+".cfs") {
		t.Errorf("%d-byte name with suffix not accessible", len(name251))
	}
	if _, err := os.Lstat(mnt + "/" + name252); !errors.Is(err, syscall.ENOENT) {
		t.Errorf("%d-byte name without suffix: want ENOENT, got %v", len(name252), err)
	}
	if _, err := os.Lstat(mnt + "/" + name252 + ".cfs"); !errors.Is(err, syscall.ENAMETOOLONG) {
		t.Errorf("%d-byte name with suffix: want ENAMETOOLONG, got %v", len(name252), err)
	}
}

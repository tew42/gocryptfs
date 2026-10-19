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
	if err := os.WriteFile(pWd+"/x.cfs", content, 0600); err != nil {
		t.Fatal(err)
	}
	// A plaintext file "gocryptfs.conf" next to the virtual config file
	conf := []byte("not the config")
	if err := os.WriteFile(dirA+"/gocryptfs.conf", conf, 0600); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(dirA + "/gocryptfs.conf")

	// Encrypted view
	cWd := dirB + "/" + wd
	if names := readdirNames(t, cWd); !slices.Equal(names, []string{"d", "f.cfs", "l.cfs", "x.cfs.cfs"}) {
		t.Errorf("wrong listing of %q: %q", cWd, names)
	}
	for _, p := range []string{cWd + "/f.cfs", cWd + "/x.cfs.cfs", dirB + "/gocryptfs.conf.cfs"} {
		if fi, err := os.Lstat(p); err != nil || !fi.Mode().IsRegular() {
			t.Errorf("%q should be a regular file: fi=%v err=%v", p, fi, err)
		}
	}
	if data, err := os.ReadFile(dirB + "/gocryptfs.conf"); err != nil || !bytes.Contains(data, []byte("FeatureFlags")) {
		t.Errorf("gocryptfs.conf should be the config file: err=%v", err)
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
	// ".cfs" maps to no plaintext name: it must not resolve to "d/d"
	if err := os.WriteFile(pWd+"/d/d", nil, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(cWd + "/d/.cfs"); !errors.Is(err, syscall.ENOENT) {
		t.Errorf("d/.cfs: want ENOENT, got %v", err)
	}
	if fi, err := os.Lstat(cWd + "/l.cfs"); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Errorf("l.cfs should be a symlink: fi=%v err=%v", fi, err)
	}
	if target, err := os.Readlink(cWd + "/l.cfs"); err != nil || target != "f" {
		t.Errorf("l.cfs: want target \"f\", got %q, err=%v", target, err)
	}

	// Round trip through the forward mount
	pWdC := dirC + "/" + wd
	if names := readdirNames(t, pWdC); !slices.Equal(names, []string{"d", "f", "l", "x.cfs"}) {
		t.Errorf("wrong listing of %q: %q", pWdC, names)
	}
	for p, want := range map[string][]byte{
		pWdC + "/f":              content,
		pWdC + "/x.cfs":          content,
		dirC + "/gocryptfs.conf": conf,
	} {
		if data, err := os.ReadFile(p); err != nil || !bytes.Equal(data, want) {
			t.Errorf("%q: want content %q, got %q, err=%v", p, want, data, err)
		}
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

// TestCfsExtNotRepresentable checks that entries that cannot be shown with
// -cfsext are skipped in the encrypted view: names that become longer than
// 255 bytes with the ".cfs" suffix, and directories whose name ends in ".cfs".
func TestCfsExtNotRepresentable(t *testing.T) {
	if !cfsext {
		t.Skip("only for -cfsext")
	}
	// Skipping an entry logs a warning, so we need -wpanic=0
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

	// Directory "x.cfs" next to file "x": "x.cfs" in the encrypted view is
	// the file. Directory "y.cfs" alone is not visible at all.
	if err := os.Mkdir(backingDir+"/x.cfs", 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(backingDir+"/x", []byte("file x"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(backingDir+"/y.cfs", 0700); err != nil {
		t.Fatal(err)
	}
	names = readdirNames(t, mnt)
	nX := 0
	for _, n := range names {
		switch n {
		case "x.cfs":
			nX++
		case "y.cfs":
			t.Errorf("%q should not be listed", n)
		}
	}
	if nX != 1 {
		t.Errorf("x.cfs should be listed exactly once, found %d times: %q", nX, names)
	}
	if fi, err := os.Lstat(mnt + "/x.cfs"); err != nil || !fi.Mode().IsRegular() {
		t.Errorf("x.cfs should be the regular file x: fi=%v err=%v", fi, err)
	}
	if _, err := os.Lstat(mnt + "/y.cfs"); !errors.Is(err, syscall.ENOENT) {
		t.Errorf("y.cfs: want ENOENT, got %v", err)
	}
}

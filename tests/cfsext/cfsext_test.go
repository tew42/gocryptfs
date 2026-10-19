package cfsext

// integration tests for "-plaintextnames -cfsext"

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"

	"github.com/pkg/xattr"
	"golang.org/x/sys/unix"

	"github.com/rfjakob/gocryptfs/v2/ctlsock"
	"github.com/rfjakob/gocryptfs/v2/internal/configfile"
	"github.com/rfjakob/gocryptfs/v2/internal/exitcodes"
	"github.com/rfjakob/gocryptfs/v2/tests/test_helpers"
)

var cDir string
var pDir string
var sock string

var testPw = []byte("test")

// Create and mount "-plaintextnames -cfsext" fs
func TestMain(m *testing.M) {
	cDir = test_helpers.InitFS(nil, "-plaintextnames", "-cfsext")
	pDir = cDir + ".mnt"
	sock = cDir + ".sock"
	test_helpers.MountOrExit(cDir, pDir, "-extpass", "echo test", "-ctlsock", sock)
	r := m.Run()
	test_helpers.UnmountPanic(pDir)
	os.Exit(r)
}

// mustExist lstat()s `path` and fails the test if it does not exist
func mustExist(t *testing.T, path string) os.FileInfo {
	t.Helper()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("%q should exist: %v", path, err)
	}
	return fi
}

// mustNotExist fails the test if `path` exists
func mustNotExist(t *testing.T, path string) {
	t.Helper()
	_, err := os.Lstat(path)
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("%q should not exist, lstat returned err=%v", path, err)
	}
}

func TestFlags(t *testing.T) {
	_, cf, err := configfile.LoadAndDecrypt(cDir+"/gocryptfs.conf", testPw)
	if err != nil {
		t.Fatal(err)
	}
	if !cf.IsFeatureFlagSet(configfile.FlagCfsExt) || !cf.IsFeatureFlagSet(configfile.FlagPlaintextNames) {
		t.Error("CfsExt and PlaintextNames flags should be set")
	}
	if cf.IsFeatureFlagSet(configfile.FlagEMENames) || cf.IsFeatureFlagSet(configfile.FlagDirIV) {
		t.Error("EMENames and DirIV flags should not be set")
	}
}

func TestFileSuffix(t *testing.T) {
	content := []byte("hello cfsext")
	if err := os.WriteFile(pDir+"/foo.txt", content, 0600); err != nil {
		t.Fatal(err)
	}
	fi := mustExist(t, cDir+"/foo.txt.cfs")
	mustNotExist(t, cDir+"/foo.txt")
	got, err := os.ReadFile(pDir + "/foo.txt")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, content) {
		t.Errorf("wrong content: %q", got)
	}
	if fi.Size() <= int64(len(content)) {
		t.Errorf("cipher file is not larger than plaintext: %d bytes", fi.Size())
	}
}

func TestDirNoSuffix(t *testing.T) {
	if err := os.Mkdir(pDir+"/dir", 0700); err != nil {
		t.Fatal(err)
	}
	if !mustExist(t, cDir+"/dir").IsDir() {
		t.Error("cipher dir is not a directory")
	}
	mustNotExist(t, cDir+"/dir.cfs")
	if err := os.Mkdir(pDir+"/dir/sub", 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pDir+"/dir/sub/file", nil, 0600); err != nil {
		t.Fatal(err)
	}
	if !mustExist(t, cDir+"/dir/sub").IsDir() {
		t.Error("cipher subdir is not a directory")
	}
	mustExist(t, cDir+"/dir/sub/file.cfs")
	mustNotExist(t, cDir+"/dir/sub/file")
}

func TestSymlinkFifo(t *testing.T) {
	if err := os.Symlink("target", pDir+"/link"); err != nil {
		t.Fatal(err)
	}
	if mustExist(t, cDir+"/link.cfs").Mode()&fs.ModeSymlink == 0 {
		t.Error("link.cfs is not a symlink")
	}
	for _, p := range []string{cDir + "/link.cfs", pDir + "/link"} {
		target, err := os.Readlink(p)
		if err != nil || target != "target" {
			t.Errorf("Readlink(%q) = %q, %v", p, target, err)
		}
	}
	if err := syscall.Mkfifo(pDir+"/fifo", 0600); err != nil {
		t.Fatal(err)
	}
	if mustExist(t, cDir+"/fifo.cfs").Mode()&fs.ModeNamedPipe == 0 {
		t.Error("fifo.cfs is not a fifo")
	}
	mustNotExist(t, cDir+"/fifo")
}

func TestReaddir(t *testing.T) {
	d := pDir + "/readdir"
	if err := os.Mkdir(d, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(d+"/file", nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(d+"/dir", 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("x", d+"/link"); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(d)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]fs.FileMode{"file": 0, "dir": fs.ModeDir, "link": fs.ModeSymlink}
	if len(entries) != len(want) {
		t.Errorf("want %d entries, got %d: %v", len(want), len(entries), entries)
	}
	for _, e := range entries {
		typ, ok := want[e.Name()]
		if !ok || e.Type() != typ {
			t.Errorf("unexpected entry %q type %v", e.Name(), e.Type())
		}
	}
	entries, err = os.ReadDir(pDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() == configfile.ConfDefaultName {
			t.Errorf("%q should be hidden", e.Name())
		}
	}
}

// A file may be named *.cfs (it is stored as *.cfs.cfs), a directory may not:
// a cipher name ends in .cfs if and only if it is not a directory.
func TestNamesEndingInCfs(t *testing.T) {
	content := []byte("x.cfs content")
	if err := os.WriteFile(pDir+"/x.cfs", content, 0600); err != nil {
		t.Fatal(err)
	}
	if !mustExist(t, cDir+"/x.cfs.cfs").Mode().IsRegular() {
		t.Error("x.cfs.cfs is not a regular file")
	}
	mustNotExist(t, cDir+"/x.cfs")
	got, err := os.ReadFile(pDir + "/x.cfs")
	if err != nil || !bytes.Equal(got, content) {
		t.Errorf("ReadFile: %q, %v", got, err)
	}
	if !test_helpers.VerifyExistence(t, pDir+"/x.cfs") {
		t.Error("x.cfs not visible")
	}
	// mkdir of a name ending in .cfs
	if err := os.Mkdir(pDir+"/d.cfs", 0700); !errors.Is(err, syscall.EINVAL) {
		t.Errorf("mkdir d.cfs: want EINVAL, got %v", err)
	}
	mustNotExist(t, cDir+"/d.cfs")
	mustNotExist(t, pDir+"/d.cfs")
	// Renaming a directory to a name ending in .cfs
	if err := os.Mkdir(pDir+"/dren", 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(pDir+"/dren", pDir+"/dren.cfs"); !errors.Is(err, syscall.EINVAL) {
		t.Errorf("rename dren -> dren.cfs: want EINVAL, got %v", err)
	}
	if !mustExist(t, pDir+"/dren").IsDir() {
		t.Error("dren is not a directory")
	}
	if !mustExist(t, cDir+"/dren").IsDir() {
		t.Error("cipher dren is not a directory")
	}
	mustNotExist(t, cDir+"/dren.cfs")
	// Renaming a file to a name ending in .cfs is fine
	if err := os.WriteFile(pDir+"/fren", []byte("fren"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(pDir+"/fren", pDir+"/fren.cfs"); err != nil {
		t.Fatalf("rename fren -> fren.cfs: %v", err)
	}
	if !mustExist(t, cDir+"/fren.cfs.cfs").Mode().IsRegular() {
		t.Error("fren.cfs.cfs is not a regular file")
	}
	mustNotExist(t, cDir+"/fren.cfs")
	mustNotExist(t, pDir+"/fren")
	got, err = os.ReadFile(pDir + "/fren.cfs")
	if err != nil || string(got) != "fren" {
		t.Errorf("ReadFile fren.cfs: %q, %v", got, err)
	}
}

func TestRename(t *testing.T) {
	// file -> file
	if err := os.WriteFile(pDir+"/ren_a", []byte("a"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(pDir+"/ren_a", pDir+"/ren_b"); err != nil {
		t.Fatal(err)
	}
	mustNotExist(t, cDir+"/ren_a.cfs")
	mustExist(t, cDir+"/ren_b.cfs")
	// dir -> dir
	if err := os.Mkdir(pDir+"/ren_da", 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(pDir+"/ren_da", pDir+"/ren_db"); err != nil {
		t.Fatal(err)
	}
	mustNotExist(t, cDir+"/ren_da")
	if !mustExist(t, cDir+"/ren_db").IsDir() {
		t.Error("ren_db is not a directory")
	}
	// file over existing file
	if err := os.WriteFile(pDir+"/ren_c", []byte("c"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(pDir+"/ren_c", pDir+"/ren_b"); err != nil {
		t.Fatal(err)
	}
	mustNotExist(t, cDir+"/ren_c.cfs")
	mustExist(t, cDir+"/ren_b.cfs")
	got, err := os.ReadFile(pDir + "/ren_b")
	if err != nil || string(got) != "c" {
		t.Errorf("ReadFile: %q, %v", got, err)
	}
}

func TestRenameExchange(t *testing.T) {
	f1, f2 := pDir+"/xchg_f1", pDir+"/xchg_f2"
	d1, d2 := pDir+"/xchg_d1", pDir+"/xchg_d2"
	if err := os.WriteFile(f1, []byte("1"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f2, []byte("2"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(d1, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(d2, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(d1+"/marker", nil, 0600); err != nil {
		t.Fatal(err)
	}
	// file <-> file
	err := unix.Renameat2(unix.AT_FDCWD, f1, unix.AT_FDCWD, f2, unix.RENAME_EXCHANGE)
	if err == unix.EINVAL {
		t.Skip("RENAME_EXCHANGE not supported by the backing filesystem")
	} else if err != nil {
		t.Fatal(err)
	}
	c1, _ := os.ReadFile(f1)
	c2, _ := os.ReadFile(f2)
	if string(c1) != "2" || string(c2) != "1" {
		t.Errorf("contents not swapped: f1=%q f2=%q", c1, c2)
	}
	mustExist(t, cDir+"/xchg_f1.cfs")
	mustExist(t, cDir+"/xchg_f2.cfs")
	// dir <-> dir
	if err := unix.Renameat2(unix.AT_FDCWD, d1, unix.AT_FDCWD, d2, unix.RENAME_EXCHANGE); err != nil {
		t.Fatal(err)
	}
	mustExist(t, cDir+"/xchg_d2/marker.cfs")
	mustNotExist(t, cDir+"/xchg_d1/marker.cfs")
	// file <-> dir and dir <-> file
	if err := unix.Renameat2(unix.AT_FDCWD, f1, unix.AT_FDCWD, d1, unix.RENAME_EXCHANGE); err != unix.EINVAL {
		t.Errorf("file<->dir: want EINVAL, got %v", err)
	}
	if err := unix.Renameat2(unix.AT_FDCWD, d1, unix.AT_FDCWD, f1, unix.RENAME_EXCHANGE); err != unix.EINVAL {
		t.Errorf("dir<->file: want EINVAL, got %v", err)
	}
}

func TestHardlink(t *testing.T) {
	if err := os.WriteFile(pDir+"/hl1", []byte("hl"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(pDir+"/hl1", pDir+"/hl2"); err != nil {
		t.Fatal(err)
	}
	st := mustExist(t, cDir+"/hl2.cfs").Sys().(*syscall.Stat_t)
	if st.Nlink != 2 {
		t.Errorf("hl2.cfs: want nlink 2, have %d", st.Nlink)
	}
	mustNotExist(t, cDir+"/hl2")
}

func TestUnlinkRmdir(t *testing.T) {
	if err := os.WriteFile(pDir+"/rm_f", nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(pDir+"/rm_d", 0700); err != nil {
		t.Fatal(err)
	}
	mustExist(t, cDir+"/rm_f.cfs")
	mustExist(t, cDir+"/rm_d")
	if err := os.Remove(pDir + "/rm_f"); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(pDir + "/rm_d"); err != nil {
		t.Fatal(err)
	}
	mustNotExist(t, cDir+"/rm_f.cfs")
	mustNotExist(t, cDir+"/rm_d")
}

// The ".cfs" suffix eats 4 of the 255 bytes for files, but not for directories
func TestNameLength(t *testing.T) {
	n251 := strings.Repeat("a", 251)
	if err := os.WriteFile(pDir+"/"+n251, nil, 0600); err != nil {
		t.Fatal(err)
	}
	mustExist(t, cDir+"/"+n251+".cfs")
	n252 := strings.Repeat("b", 252)
	err := os.WriteFile(pDir+"/"+n252, nil, 0600)
	if !errors.Is(err, syscall.ENAMETOOLONG) {
		t.Errorf("252-byte name: want ENAMETOOLONG, got %v", err)
	}
	if err := os.Mkdir(pDir+"/"+strings.Repeat("d", 255), 0700); err != nil {
		t.Errorf("255-byte dir name: %v", err)
	}
}

func TestCtlSock(t *testing.T) {
	if err := os.Mkdir(pDir+"/ctl_d", 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pDir+"/ctl_f", nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pDir+"/ctl_d/f", nil, 0600); err != nil {
		t.Fatal(err)
	}
	check := func(req ctlsock.RequestStruct, want string) {
		t.Helper()
		resp := test_helpers.QueryCtlSock(t, sock, req)
		if resp.ErrNo != 0 || resp.Result != want {
			t.Errorf("%+v: want %q, got %+v", req, want, resp)
		}
	}
	check(ctlsock.RequestStruct{EncryptPath: "ctl_f"}, "ctl_f.cfs")
	check(ctlsock.RequestStruct{EncryptPath: "ctl_d"}, "ctl_d")
	check(ctlsock.RequestStruct{EncryptPath: "ctl_d/f"}, "ctl_d/f.cfs")
	check(ctlsock.RequestStruct{EncryptPath: "ctl_nope"}, "ctl_nope.cfs")
	check(ctlsock.RequestStruct{DecryptPath: "ctl_f.cfs"}, "ctl_f")
	check(ctlsock.RequestStruct{DecryptPath: "ctl_d"}, "ctl_d")
	check(ctlsock.RequestStruct{DecryptPath: "ctl_d/f.cfs"}, "ctl_d/f")
}

func TestXattr(t *testing.T) {
	fn := pDir + "/xattr_f"
	if err := os.WriteFile(fn, nil, 0600); err != nil {
		t.Fatal(err)
	}
	val := []byte("xattr value")
	err := xattr.LSet(fn, "user.test", val)
	if errors.Is(err, syscall.ENOTSUP) {
		t.Skip(err)
	} else if err != nil {
		t.Fatal(err)
	}
	got, err := xattr.LGet(fn, "user.test")
	if err != nil || !bytes.Equal(got, val) {
		t.Errorf("LGet: %q, %v", got, err)
	}
	// The (encrypted) xattr must be attached to the suffixed cipher file
	names, err := xattr.LList(cDir + "/xattr_f.cfs")
	if err != nil || len(names) == 0 {
		t.Errorf("xattr_f.cfs has no xattrs: %v, %v", names, err)
	}
}

// Runs after the tests above have populated the fs with all kinds of entries
func TestFsckClean(t *testing.T) {
	cmd := exec.Command(test_helpers.GocryptfsBinary, "-fsck", "-extpass", "echo test", cDir)
	out, err := cmd.CombinedOutput()
	if code := test_helpers.ExtractCmdExitCode(err); code != 0 {
		t.Log(string(out))
		t.Errorf("fsck returned code %d but fs should be clean", code)
	}
}

// -zerokey reads no config, so -cfsext must be passed on the command line
func TestZerokeyMount(t *testing.T) {
	c2, err := os.MkdirTemp(test_helpers.TmpDir, "zerokey.")
	if err != nil {
		t.Fatal(err)
	}
	p2 := c2 + ".mnt"
	test_helpers.MountOrFatal(t, c2, p2, "-zerokey", "-plaintextnames", "-cfsext")
	defer test_helpers.UnmountPanic(p2)
	if err := os.WriteFile(p2+"/name", nil, 0600); err != nil {
		t.Fatal(err)
	}
	mustExist(t, c2+"/name.cfs")
	mustNotExist(t, c2+"/name")
}

// The CfsExt feature flag in gocryptfs.conf applies without -cfsext on the command line
func TestConfWins(t *testing.T) {
	c := test_helpers.InitFS(t, "-plaintextnames", "-cfsext")
	p := c + ".mnt"
	test_helpers.MountOrFatal(t, c, p, "-extpass", "echo test")
	defer test_helpers.UnmountPanic(p)
	if err := os.WriteFile(p+"/name", nil, 0600); err != nil {
		t.Fatal(err)
	}
	mustExist(t, c+"/name.cfs")
	mustNotExist(t, c+"/name")
}

// Non-directory cipher entries without suffix and directories ending in .cfs
// are hidden (with a warning, hence -wpanic=0). When both "a" (dir) and
// "a.cfs" (file) exist, the file wins and the directory is hidden.
// -fsck reports all of them.
func TestHiddenEntries(t *testing.T) {
	c3 := test_helpers.InitFS(t, "-plaintextnames", "-cfsext")
	p3 := c3 + ".mnt"
	test_helpers.MountOrFatal(t, c3, p3, "-extpass", "echo test", "-wpanic=0")
	// Unmounted explicitly before fsck; this only cleans up after t.Fatal
	mounted := true
	defer func() {
		if mounted {
			test_helpers.UnmountPanic(p3)
		}
	}()
	if err := os.WriteFile(c3+"/plain.txt", []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	// Get a valid encrypted file without the kernel ever looking up "a"
	content := []byte("file a")
	if err := os.WriteFile(p3+"/a_src", content, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(c3+"/a_src.cfs", c3+"/a.cfs"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(c3+"/a", 0700); err != nil {
		t.Fatal(err)
	}
	// A directory ending in .cfs can only be created out of band
	if err := os.Mkdir(c3+"/h.cfs", 0700); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(p3 + "/a")
	if err != nil {
		t.Fatal(err)
	}
	if !fi.Mode().IsRegular() {
		t.Errorf("a: want regular file, got %v", fi.Mode())
	}
	got, err := os.ReadFile(p3 + "/a")
	if err != nil || !bytes.Equal(got, content) {
		t.Errorf("ReadFile: %q, %v", got, err)
	}
	if _, err := os.Stat(p3 + "/plain.txt"); !errors.Is(err, syscall.ENOENT) {
		t.Errorf("plain.txt: want ENOENT, got %v", err)
	}
	if _, err := os.Stat(p3 + "/h.cfs"); !errors.Is(err, syscall.ENOENT) {
		t.Errorf("h.cfs: want ENOENT, got %v", err)
	}
	entries, err := os.ReadDir(p3)
	if err != nil {
		t.Fatal(err)
	}
	nA := 0
	for _, e := range entries {
		switch e.Name() {
		case "plain.txt", "h.cfs":
			t.Errorf("%q should be hidden", e.Name())
		case "a":
			nA++
		}
	}
	if nA != 1 {
		t.Errorf("a should be listed exactly once, found %d times: %v", nA, entries)
	}
	if fi, err := os.Lstat(p3 + "/a"); err != nil || !fi.Mode().IsRegular() {
		t.Errorf("a after readdir: want regular file, got fi=%v err=%v", fi, err)
	}

	// fsck mounts the filesystem itself
	test_helpers.UnmountPanic(p3)
	mounted = false
	cmd := exec.Command(test_helpers.GocryptfsBinary, "-fsck", "-extpass", "echo test", c3)
	out, err := cmd.CombinedOutput()
	if code := test_helpers.ExtractCmdExitCode(err); code != exitcodes.FsckErrors {
		t.Errorf("fsck: want exit code %d, got %d", exitcodes.FsckErrors, code)
	}
	for _, want := range []string{"plain.txt", "shadowed", "h.cfs"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("fsck output does not mention %q", want)
		}
	}
	if t.Failed() {
		t.Log(string(out))
	}
}

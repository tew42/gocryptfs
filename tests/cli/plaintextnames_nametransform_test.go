package cli

import (
	"errors"
	"os"
	"syscall"
	"testing"

	"github.com/pkg/xattr"

	"github.com/rfjakob/gocryptfs/v2/tests/test_helpers"
)

// TestPlaintextnamesZerokeyXattr checks that xattr operations work on a
// "-zerokey -plaintextnames" mount. The xattr code always encrypts xattr
// names, so the nametransform must be initialized even with -plaintextnames.
func TestPlaintextnamesZerokeyXattr(t *testing.T) {
	cDir, err := os.MkdirTemp(test_helpers.TmpDir, t.Name()+".")
	if err != nil {
		t.Fatal(err)
	}
	pDir := cDir + ".mnt"
	test_helpers.MountOrFatal(t, cDir, pDir, "-zerokey", "-plaintextnames")
	defer test_helpers.UnmountPanic(pDir)

	file := pDir + "/file"
	if err := os.WriteFile(file, nil, 0600); err != nil {
		t.Fatal(err)
	}
	err = xattr.LSet(file, "user.test", []byte("v"))
	if errors.Is(err, syscall.ENOTSUP) {
		t.Skip("xattrs not supported by the backing filesystem")
	}
	if err != nil {
		t.Fatal(err)
	}
	val, err := xattr.LGet(file, "user.test")
	if err != nil {
		t.Fatal(err)
	}
	if string(val) != "v" {
		t.Errorf("wrong xattr value: %q", string(val))
	}
}

// TestStrayPlaintextnamesFlag checks that passing -plaintextnames when
// mounting a filesystem with encrypted names does not break the mount: the
// config file, not the command line, decides whether names are encrypted.
func TestStrayPlaintextnamesFlag(t *testing.T) {
	cDir := test_helpers.InitFS(t)
	pDir := cDir + ".mnt"
	test_helpers.MountOrFatal(t, cDir, pDir, "-extpass", "echo test", "-plaintextnames")
	defer test_helpers.UnmountPanic(pDir)

	file := pDir + "/file"
	if err := os.WriteFile(file, []byte("content"), 0600); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "content" {
		t.Errorf("wrong content: %q", string(content))
	}
}

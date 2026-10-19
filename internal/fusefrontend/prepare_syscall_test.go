package fusefrontend

import (
	"context"
	"os"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/hanwen/go-fuse/v2/fuse"

	"github.com/rfjakob/gocryptfs/v2/internal/syscallcompat"
	"github.com/rfjakob/gocryptfs/v2/tests/test_helpers"
)

func TestPrepareAtSyscall(t *testing.T) {
	cipherdir := test_helpers.InitFS(t)
	t.Logf("cipherdir = %q", cipherdir)
	args := Args{
		Cipherdir: cipherdir,
	}
	rn := newTestFS(args)
	out := &fuse.EntryOut{}

	child, errno := rn.Mkdir(context.TODO(), "dir1", 0700, out)
	if errno != 0 {
		t.Fatal(errno)
	}
	rn.AddChild("dir1", child, false)
	dir1 := toNode(child.Operations())
	_, errno = dir1.Mkdir(context.TODO(), "dir2", 0700, out)
	if errno != 0 {
		t.Fatal(errno)
	}

	dirfd, cName, errno := rn.prepareAtSyscallMyself()
	if errno != 0 {
		t.Fatal(errno)
	}
	if cName != "." {
		t.Fatal("cName should be .")
	}
	syscall.Close(dirfd)

	// Again, but populate the cache for "" by looking up a non-existing file
	rn.Lookup(context.TODO(), "xyz1234", &fuse.EntryOut{})
	dirfd, cName, errno = rn.prepareAtSyscallMyself()
	if errno != 0 {
		t.Fatal(errno)
	}
	if cName != "." {
		t.Fatal("cName should be .")
	}

	err := syscallcompat.Faccessat(dirfd, cName, unix.R_OK)
	if err != nil {
		t.Error(err)
	}
	err = syscallcompat.Faccessat(dirfd, ".", unix.R_OK)
	if err != nil {
		t.Error(err)
	}
	syscall.Close(dirfd)

	dirfd, cName, errno = rn.prepareAtSyscall("dir1", childDir)
	if errno != 0 {
		t.Fatal(errno)
	}
	if cName == "" {
		t.Fatal("cName should not be empty")
	}
	err = syscallcompat.Faccessat(dirfd, cName, unix.R_OK)
	if err != nil {
		t.Error(err)
	}
	syscall.Close(dirfd)

	dirfd, cName, errno = dir1.prepareAtSyscall("dir2", childDir)
	if errno != 0 {
		t.Fatal(errno)
	}
	if cName == "" {
		t.Fatal("cName should not be empty")
	}
	err = syscallcompat.Faccessat(dirfd, cName, unix.R_OK)
	if err != nil {
		t.Errorf("Faccessat(%d, %q): %v", dirfd, cName, err)
	}
	syscall.Close(dirfd)

	n255 := strings.Repeat("n", 255)
	dir1.Mkdir(context.TODO(), n255, 0700, out)
	dirfd, cName, errno = dir1.prepareAtSyscall(n255, childDir)
	if errno != 0 {
		t.Fatal(errno)
	}
	if cName == "" {
		t.Fatal("cName should not be empty")
	}
	if len(cName) >= 255 {
		t.Fatalf("cName is too long: %q", cName)
	}
	err = syscallcompat.Faccessat(dirfd, cName, unix.R_OK)
	if err != nil {
		t.Errorf("Faccessat(%d, %q): %v", dirfd, cName, err)
	}
	syscall.Close(dirfd)
}

func TestPrepareAtSyscallPlaintextnames(t *testing.T) {
	cipherdir := test_helpers.InitFS(t, "-plaintextnames")
	args := Args{
		Cipherdir:      cipherdir,
		PlaintextNames: true,
	}
	rn := newTestFS(args)
	out := &fuse.EntryOut{}

	child, errno := rn.Mkdir(context.TODO(), "dir1", 0700, out)
	if errno != 0 {
		t.Fatal(errno)
	}
	rn.AddChild("dir1", child, false)
	dir1 := toNode(child.Operations())
	_, errno = dir1.Mkdir(context.TODO(), "dir2", 0700, out)
	if errno != 0 {
		t.Fatal(errno)
	}

	dirfd, cName, errno := rn.prepareAtSyscallMyself()
	if errno != 0 {
		t.Fatal(errno)
	}
	if cName != "." {
		t.Fatal("cName should be .")
	}
	err := syscallcompat.Faccessat(dirfd, cName, unix.R_OK)
	if err != nil {
		t.Error(err)
	}
	err = syscallcompat.Faccessat(dirfd, ".", unix.R_OK)
	if err != nil {
		t.Error(err)
	}
	syscall.Close(dirfd)

	dirfd, cName, errno = rn.prepareAtSyscall("dir1", childDir)
	if errno != 0 {
		t.Fatal(errno)
	}
	if cName != "dir1" {
		t.Fatalf("wrong cName: %q", cName)
	}
	err = syscallcompat.Faccessat(dirfd, cName, unix.R_OK)
	if err != nil {
		t.Error(err)
	}
	syscall.Close(dirfd)

	dirfd, cName, errno = dir1.prepareAtSyscall("dir2", childDir)
	if errno != 0 {
		t.Fatal(errno)
	}
	if cName != "dir2" {
		t.Fatalf("wrong cName: %q", cName)
	}
	err = syscallcompat.Faccessat(dirfd, cName, unix.R_OK)
	if err != nil {
		t.Error(err)
	}
	syscall.Close(dirfd)
}

func TestPrepareAtSyscallCfsExt(t *testing.T) {
	cipherdir := test_helpers.InitFS(t, "-plaintextnames", "-cfsext")
	args := Args{
		Cipherdir:      cipherdir,
		PlaintextNames: true,
		CfsExt:         true,
	}
	rn := newTestFS(args)
	out := &fuse.EntryOut{}

	child, errno := rn.Mkdir(context.TODO(), "dir1", 0700, out)
	if errno != 0 {
		t.Fatal(errno)
	}
	rn.AddChild("dir1", child, false)
	dir1 := toNode(child.Operations())
	if err := os.WriteFile(cipherdir+"/f.cfs", nil, 0600); err != nil {
		t.Fatal(err)
	}

	// Mapping
	dirfd, cName, errno := rn.prepareAtSyscall("new", childNonDir)
	if errno != 0 {
		t.Fatal(errno)
	}
	syscall.Close(dirfd)
	if cName != "new.cfs" {
		t.Errorf("wrong cName: %q", cName)
	}
	dirfd, cName, errno = rn.prepareAtSyscall("new", childDir)
	if errno != 0 {
		t.Fatal(errno)
	}
	syscall.Close(dirfd)
	if cName != "new" {
		t.Errorf("wrong cName: %q", cName)
	}

	// Lookup rule
	dirfd, _, errno = rn.prepareAtSyscallMyself()
	if errno != 0 {
		t.Fatal(errno)
	}
	defer syscall.Close(dirfd)
	cName, st, errno := rn.resolveChildCfsExt(dirfd, "f")
	if errno != 0 || cName != "f.cfs" || st.Mode&syscall.S_IFMT == syscall.S_IFDIR {
		t.Errorf("f: cName=%q errno=%v", cName, errno)
	}
	cName, st, errno = rn.resolveChildCfsExt(dirfd, "dir1")
	if errno != 0 || cName != "dir1" || st.Mode&syscall.S_IFMT != syscall.S_IFDIR {
		t.Errorf("dir1: cName=%q errno=%v", cName, errno)
	}
	_, _, errno = rn.resolveChildCfsExt(dirfd, "nope")
	if errno != syscall.ENOENT {
		t.Errorf("nope: want ENOENT, got %v", errno)
	}

	// Lookup
	ch, errno := rn.Lookup(context.TODO(), "f", &fuse.EntryOut{})
	if errno != 0 || ch.IsDir() {
		t.Errorf("Lookup f: errno=%v", errno)
	}
	ch, errno = rn.Lookup(context.TODO(), "dir1", &fuse.EntryOut{})
	if errno != 0 || !ch.IsDir() {
		t.Errorf("Lookup dir1: errno=%v", errno)
	}

	dirfd2, cName, errno := dir1.prepareAtSyscallMyself()
	if errno != 0 {
		t.Fatal(errno)
	}
	syscall.Close(dirfd2)
	if cName != "dir1" {
		t.Errorf("wrong cName: %q", cName)
	}
}

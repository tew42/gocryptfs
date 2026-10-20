package fusefrontend

import (
	"errors"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/hanwen/go-fuse/v2/fs"

	"github.com/rfjakob/gocryptfs/v2/internal/nametransform"
	"github.com/rfjakob/gocryptfs/v2/internal/syscallcompat"
)

// CfsExtSuffix is appended to the names of non-directory entries when
// Args.CfsExt is set
const CfsExtSuffix = ".cfs"

// HasCfsExtSuffix reports whether name ends in CfsExtSuffix in any letter
// case (ASCII). This is the test for directory names: Windows file systems
// are case-insensitive, so cppcryptfs cannot represent a directory "x.CFS"
// either. Non-directories are only ever written with the lowercase suffix.
func HasCfsExtSuffix(name string) bool {
	n := len(name) - len(CfsExtSuffix)
	return n >= 0 && strings.ToLower(name[n:]) == CfsExtSuffix
}

// childType tells prepareAtSyscall what kind of directory entry `child` is.
// Only relevant with -cfsext, where non-directories get the ".cfs" suffix.
type childType uint8

const (
	childAny childType = iota // unknown; caller resolves (see cfsExtResolve)
	childDir
	childNonDir
)

func childTypeOf(isDir bool) childType {
	if isDir {
		return childDir
	}
	return childNonDir
}

// cfsExtCName returns the ciphertext name for plaintext `name` of type `ct`.
func (rn *RootNode) cfsExtCName(name string, ct childType) string {
	if rn.args.CfsExt && ct == childNonDir {
		return name + CfsExtSuffix
	}
	return name
}

// cfsExtResolve finds the cipher entry for plaintext `name` in `dirfd`:
// "name.cfs" if it is not a directory, else "name" if it is a directory
// and does not end in ".cfs" in any letter case.
func (rn *RootNode) cfsExtResolve(dirfd int, name string) (cName string, st *syscall.Stat_t, errno syscall.Errno) {
	st, err := syscallcompat.Fstatat2(dirfd, name+CfsExtSuffix, unix.AT_SYMLINK_NOFOLLOW)
	if err == nil && uint32(st.Mode)&syscall.S_IFMT != syscall.S_IFDIR {
		return name + CfsExtSuffix, st, 0
	}
	if err != nil && !errors.Is(err, syscall.ENOENT) && !errors.Is(err, syscall.ENAMETOOLONG) {
		return "", nil, fs.ToErrno(err)
	}
	if HasCfsExtSuffix(name) {
		// A suffixed name is never a directory
		return "", nil, syscall.ENOENT
	}
	st, err = syscallcompat.Fstatat2(dirfd, name, unix.AT_SYMLINK_NOFOLLOW)
	if err != nil {
		return "", nil, fs.ToErrno(err)
	}
	if uint32(st.Mode)&syscall.S_IFMT != syscall.S_IFDIR {
		return "", nil, syscall.ENOENT
	}
	return name, st, 0
}

// cfsExtPlainName returns the plaintext name of cipher entry `cName` with
// file type `mode`, or false if the entry must be hidden.
// Directories ending in ".cfs" in any letter case are hidden.
func cfsExtPlainName(cName string, mode uint32) (string, bool) {
	if mode&syscall.S_IFMT == syscall.S_IFDIR {
		if HasCfsExtSuffix(cName) {
			return "", false
		}
		return cName, true
	}
	name, ok := strings.CutSuffix(cName, CfsExtSuffix)
	if !ok || nametransform.IsValidName(name) != nil {
		return "", false
	}
	return name, true
}

// cfsExtShadowed returns true if directory `cName` is shadowed by a
// non-directory "cName.cfs" (which wins in Lookup).
func (f *File) cfsExtShadowed(cName string) bool {
	st, err := syscallcompat.Fstatat2(f.intFd(), cName+CfsExtSuffix, unix.AT_SYMLINK_NOFOLLOW)
	return err == nil && uint32(st.Mode)&syscall.S_IFMT != syscall.S_IFDIR
}

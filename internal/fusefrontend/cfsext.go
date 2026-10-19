package fusefrontend

import (
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/hanwen/go-fuse/v2/fs"

	"github.com/rfjakob/gocryptfs/v2/internal/nametransform"
	"github.com/rfjakob/gocryptfs/v2/internal/syscallcompat"
)

// childType tells prepareAtSyscall what kind of directory entry `child` is.
// Only relevant with -cfsext, where non-directories get the ".cfs" suffix.
type childType uint8

const (
	childAny childType = iota // unknown; caller resolves (see resolveChildCfsExt)
	childDir
	childNonDir
)

func childTypeOf(isDir bool) childType {
	if isDir {
		return childDir
	}
	return childNonDir
}

// cNameCfsExt returns the ciphertext name for plaintext `name` of type `ct`.
func (rn *RootNode) cNameCfsExt(name string, ct childType) string {
	if rn.args.CfsExt && ct == childNonDir {
		return name + CfsExtSuffix
	}
	return name
}

// resolveChildCfsExt finds the cipher entry for plaintext `name` in `dirfd`:
// "name.cfs" if it is not a directory, else "name" if it is a directory.
func (rn *RootNode) resolveChildCfsExt(dirfd int, name string) (cName string, st *syscall.Stat_t, errno syscall.Errno) {
	st, err := syscallcompat.Fstatat2(dirfd, name+CfsExtSuffix, unix.AT_SYMLINK_NOFOLLOW)
	if err == nil && uint32(st.Mode)&syscall.S_IFMT != syscall.S_IFDIR {
		return name + CfsExtSuffix, st, 0
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

// childTypeCfsExt returns the type of the existing child `name` of `n`.
func (n *Node) childTypeCfsExt(dirfd int, name string) (childType, syscall.Errno) {
	if ch := n.GetChild(name); ch != nil {
		return childTypeOf(ch.IsDir()), 0
	}
	_, st, errno := n.rootNode().resolveChildCfsExt(dirfd, name)
	if errno != 0 {
		return childAny, errno
	}
	return childTypeOf(uint32(st.Mode)&syscall.S_IFMT == syscall.S_IFDIR), 0
}

// plainNameCfsExt returns the plaintext name of cipher entry `cName` with
// file type `mode`, or false if the entry must be hidden.
func plainNameCfsExt(cName string, mode uint32) (string, bool) {
	if mode&syscall.S_IFMT == syscall.S_IFDIR {
		return cName, true
	}
	name, ok := strings.CutSuffix(cName, CfsExtSuffix)
	if !ok || nametransform.IsValidName(name) != nil {
		return "", false
	}
	return name, true
}

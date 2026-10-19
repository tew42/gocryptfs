package fusefrontend_reverse

import (
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/rfjakob/gocryptfs/v2/internal/ctlsocksrv"
	"github.com/rfjakob/gocryptfs/v2/internal/fusefrontend"
	"github.com/rfjakob/gocryptfs/v2/internal/syscallcompat"
)

// Verify that the interface is implemented.
var _ ctlsocksrv.Interface = &RootNode{}

// EncryptPath implements ctlsock.Backend.
// This is used for the control socket and for the "-exclude" logic.
func (rn *RootNode) EncryptPath(plainPath string) (string, error) {
	if (rn.args.PlaintextNames && !rn.args.CfsExt) || plainPath == "" {
		return plainPath, nil
	}
	if rn.args.CfsExt {
		// Directories keep their name, everything else (including
		// entries that do not exist) gets CfsExtSuffix. Directories
		// named *.cfs are not representable.
		dirfd, err := syscallcompat.OpenDirNofollow(rn.args.Cipherdir, filepath.Dir(plainPath))
		if err != nil {
			return "", err
		}
		defer syscall.Close(dirfd)
		st, err := syscallcompat.Fstatat2(dirfd, filepath.Base(plainPath), unix.AT_SYMLINK_NOFOLLOW)
		if err == nil && st.Mode&syscall.S_IFMT == syscall.S_IFDIR {
			if strings.HasSuffix(plainPath, fusefrontend.CfsExtSuffix) {
				return "", syscall.ENOENT
			}
			return plainPath, nil
		}
		return plainPath + fusefrontend.CfsExtSuffix, nil
	}
	cipherPath := ""
	parts := strings.Split(plainPath, "/")
	for _, part := range parts {
		dirIV := rn.deriveDirIV(cipherPath)
		encryptedPart, err := rn.nameTransform.EncryptName(part, dirIV)
		if err != nil {
			return "", err
		}
		if rn.args.LongNames && (len(encryptedPart) > unix.NAME_MAX || len(encryptedPart) > rn.nameTransform.GetLongNameMax()) {
			encryptedPart = rn.nameTransform.HashLongName(encryptedPart)
		}
		cipherPath = filepath.Join(cipherPath, encryptedPart)
	}
	return cipherPath, nil
}

// DecryptPath implements ctlsock.Backend
func (rn *RootNode) DecryptPath(cipherPath string) (string, error) {
	if rn.args.CfsExt && cipherPath != "" {
		dirfd, pPath, err := rn.openBackingDir(cipherPath, childAny)
		if err != nil {
			return "", err
		}
		syscall.Close(dirfd)
		return pPath, nil
	}
	p, err := rn.decryptPath(cipherPath)
	return p, err
}

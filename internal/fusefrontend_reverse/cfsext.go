package fusefrontend_reverse

// childType tells openBackingDir what kind of entry the last path component
// refers to. Only used with -cfsext.
type childType uint8

const (
	childAny    childType = iota // unknown: resolve by probing the backing directory
	childDir                     // directory: name is used unchanged
	childNonDir                  // non-directory: name must carry CfsExtSuffix
)

// childTypeOf returns childDir or childNonDir.
func childTypeOf(isDir bool) childType {
	if isDir {
		return childDir
	}
	return childNonDir
}

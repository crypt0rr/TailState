//go:build !unix

package store

// copyOwner is a no-op on platforms that do not model ownership as a numeric
// uid and gid. Compact calls it only when running as root, which does not
// exist on those platforms.
func copyOwner(string, string) error { return nil }

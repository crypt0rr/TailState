//go:build !unix

package main

// restrictFileCreationMask is a no-op where the platform has no umask; the
// store still creates its database files with owner-only permissions.
func restrictFileCreationMask() int { return 0 }

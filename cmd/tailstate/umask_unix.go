//go:build unix

package main

import "syscall"

// restrictFileCreationMask makes every file and directory the process creates
// (the SQLite database, its -wal/-shm sidecars, and exported evidence) private
// to the service user, independent of the umask inherited from the host or
// container runtime. It returns the previous mask.
func restrictFileCreationMask() int {
	return syscall.Umask(0o077)
}

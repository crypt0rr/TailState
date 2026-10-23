//go:build unix

package store

import (
	"fmt"
	"os"
	"syscall"
)

// fileOwner returns the numeric owner and group of the file described by info.
func fileOwner(info os.FileInfo) (uid, gid int, ok bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return int(stat.Uid), int(stat.Gid), true
}

// copyOwner gives the file at to the owner and group of the file at from. It
// fails rather than leaving the owner unchanged when the owner cannot be read,
// because callers use it to keep a root-owned replacement from taking over.
func copyOwner(from, to string) error {
	info, err := os.Stat(from)
	if err != nil {
		return err
	}
	uid, gid, ok := fileOwner(info)
	if !ok {
		return fmt.Errorf("read owner of %s", from)
	}
	return os.Chown(to, uid, gid)
}

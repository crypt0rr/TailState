//go:build unix

package store

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// ServiceLock is an advisory, non-blocking flock(2) on DATABASE.lock. serve
// holds it for its lifetime and offline maintenance (admin compact) takes it
// before touching the database, so compaction refuses to run while the
// service is up. The kernel releases the lock when the process exits, so a
// crash never leaves a stale lock. Containers sharing the data volume on one
// host observe the same lock.
type ServiceLock struct {
	file *os.File
}

// ErrServiceRunning reports that another process holds the service lock.
var ErrServiceRunning = errors.New("TailState appears to be running against this database (its service lock is held); stop the service and retry")

// LockService acquires the service lock for the database at path, creating
// the owner-only lock file beside it if necessary.
func LockService(path string) (*ServiceLock, error) {
	file, err := os.OpenFile(serviceLockPath(path), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open service lock: %w", err)
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, ErrServiceRunning
		}
		return nil, fmt.Errorf("acquire service lock: %w", err)
	}
	return &ServiceLock{file: file}, nil
}

// Release drops the lock. The lock file itself is left in place; removing it
// would let a concurrent opener lock a different inode.
func (l *ServiceLock) Release() error {
	if l == nil || l.file == nil {
		return nil
	}
	err := l.file.Close()
	l.file = nil
	return err
}

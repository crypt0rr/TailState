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

// MaintenanceLock is an advisory flock(2) on DATABASE.maintenance.lock that
// orders the two administrative commands which depend on which file is the
// live database. admin reset takes it shared while it writes its token; admin
// compact takes it exclusive from before it copies the database until the
// replacement is renamed into place. A token written during a compaction
// would otherwise land in the file the rename discards. It is separate from
// ServiceLock because reset must keep working while serve holds that lock.
// Both sides are non-blocking, so the later command fails with
// ErrMaintenanceBusy instead of waiting.
type MaintenanceLock struct {
	file *os.File
}

// LockMaintenanceShared takes the maintenance lock shared, as admin reset does.
// Any number of resets may hold it at once.
func LockMaintenanceShared(path string) (*MaintenanceLock, error) {
	return lockMaintenance(path, syscall.LOCK_SH)
}

// LockMaintenanceExclusive takes the maintenance lock exclusive, as admin
// compact does.
func LockMaintenanceExclusive(path string) (*MaintenanceLock, error) {
	return lockMaintenance(path, syscall.LOCK_EX)
}

func lockMaintenance(path string, how int) (*MaintenanceLock, error) {
	file, err := os.OpenFile(maintenanceLockPath(path), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open maintenance lock: %w", err)
	}
	if err := syscall.Flock(int(file.Fd()), how|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, ErrMaintenanceBusy
		}
		return nil, fmt.Errorf("acquire maintenance lock: %w", err)
	}
	return &MaintenanceLock{file: file}, nil
}

// Release drops the maintenance lock. Like ServiceLock, it leaves the lock
// file in place.
func (l *MaintenanceLock) Release() error {
	if l == nil || l.file == nil {
		return nil
	}
	err := l.file.Close()
	l.file = nil
	return err
}

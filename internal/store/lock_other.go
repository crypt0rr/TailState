//go:build !unix

package store

import "errors"

// ServiceLock is a no-op on platforms without flock(2); stop the service
// before running offline maintenance there.
type ServiceLock struct{}

// ErrServiceRunning reports that another process holds the service lock.
var ErrServiceRunning = errors.New("TailState appears to be running against this database (its service lock is held); stop the service and retry")

// LockService always succeeds on platforms without flock(2).
func LockService(string) (*ServiceLock, error) { return &ServiceLock{}, nil }

// Release is a no-op.
func (*ServiceLock) Release() error { return nil }

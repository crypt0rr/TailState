//go:build race

package store

// raceDetectorEnabled lets large fixtures scale down under -race, where the
// instrumented pure-Go SQLite build is an order of magnitude slower.
const raceDetectorEnabled = true

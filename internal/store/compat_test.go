package store

import (
	"context"

	"github.com/crypt0rr/tailstate/internal/model"
)

// applyBatch keeps slice-oriented assertions concise without keeping a
// compatibility method in the Store API. Live callers should use
// ApplyBatchWithBatch so trigger correlation and batch metadata remain visible.
func (s *Store) applyBatch(ctx context.Context, generation int64, results []model.Collected, digest func([]model.Change) string) ([]model.Change, error) {
	batch, err := s.ApplyBatchWithBatch(ctx, generation, results, digest)
	return batch.Changes, err
}

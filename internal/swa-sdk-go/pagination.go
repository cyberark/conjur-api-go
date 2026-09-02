package swa

import (
	"context"
	"iter"
)

// defaultPageSize is the page size used by the auto-paginating iterators when
// the caller does not specify one. It matches the server-side default.
const defaultPageSize int32 = 100

// ListOptions controls a single page of a list request. Leave it nil (or use
// the zero value) to accept the server defaults.
type ListOptions struct {
	// Limit is the maximum number of items to return in one page (1-1000).
	Limit int32
	// Offset is the number of items to skip before returning results.
	Offset int32
}

func (o *ListOptions) limit() *int32 {
	if o == nil || o.Limit == 0 {
		return nil
	}
	l := o.Limit
	return &l
}

func (o *ListOptions) offset() *int32 {
	if o == nil || o.Offset == 0 {
		return nil
	}
	off := o.Offset
	return &off
}

// paginate returns an iterator that walks every item across all pages using
// offset-based pagination. It is generic over the item type so every list
// endpoint gets the same lazy, allocation-light traversal.
//
// The iterator yields (item, nil) for each element in order; if a page request
// fails it yields (zero, err) once and stops. Callers using range-over-func can
// simply `for item, err := range client.TrustDomains().All(ctx, nil)`.
func paginate[T any](ctx context.Context, pageSize int32, page func(ctx context.Context, limit, offset int32) ([]T, error)) iter.Seq2[T, error] {
	if pageSize <= 0 {
		pageSize = defaultPageSize
	}
	return func(yield func(T, error) bool) {
		var offset int32
		for {
			if err := ctx.Err(); err != nil {
				var zero T
				yield(zero, err)
				return
			}
			items, err := page(ctx, pageSize, offset)
			if err != nil {
				var zero T
				yield(zero, err)
				return
			}
			for i := range items {
				if !yield(items[i], nil) {
					return
				}
			}
			// A short page (fewer than requested) means we've reached the end.
			if int32(len(items)) < pageSize {
				return
			}
			offset += int32(len(items))
		}
	}
}

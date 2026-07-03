package store

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/arhuman/prooflog/internal/api"
)

// walkHolds pages through ListHolds with the given page size and returns the
// concatenated hold ids plus the per-page counts, asserting no id repeats.
func walkHolds(t *testing.T, s *Store, source string, pageSize uint32) (ids []string, pageCounts []int) {
	t.Helper()
	ctx := context.Background()
	seen := map[string]bool{}
	token := ""
	for {
		resp, err := s.ListHolds(ctx, &api.ListHoldsRequest{
			SourceId: source, PageSize: pageSize, PageToken: token,
		})
		if err != nil {
			t.Fatal(err)
		}
		pageCounts = append(pageCounts, len(resp.Holds))
		for _, h := range resp.Holds {
			if seen[h.HoldId] {
				t.Fatalf("hold %s returned twice across pages", h.HoldId)
			}
			seen[h.HoldId] = true
			ids = append(ids, h.HoldId)
		}
		if resp.NextPageToken == "" {
			break
		}
		token = resp.NextPageToken
	}
	return ids, pageCounts
}

func TestListHoldsPagination(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	const source = "vps-01/api"

	want := map[string]bool{}
	for i := 0; i < 7; i++ {
		h, err := s.PlaceHold(ctx, &api.PlaceHoldRequest{
			SourceId: source, Reason: fmt.Sprintf("audit-%d", i),
		})
		if err != nil {
			t.Fatal(err)
		}
		want[h.HoldId] = true
	}

	// Walk in pages of 3: 3 + 3 + 1, final token empty, no duplicates.
	ids, counts := walkHolds(t, s, source, 3)
	if fmt.Sprint(counts) != "[3 3 1]" {
		t.Fatalf("want page counts [3 3 1], got %v", counts)
	}
	if len(ids) != len(want) {
		t.Fatalf("want %d holds across pages, got %d", len(want), len(ids))
	}
	for _, id := range ids {
		if !want[id] {
			t.Fatalf("paged hold %s not in seeded set", id)
		}
	}

	// PageSize 0 defaults to the full page: everything in one shot, empty token.
	all, allCounts := walkHolds(t, s, source, 0)
	if len(allCounts) != 1 || allCounts[0] != len(want) {
		t.Fatalf("PageSize 0 should return all %d holds in one page, got counts %v", len(want), allCounts)
	}
	if len(all) != len(want) {
		t.Fatalf("PageSize 0 returned %d holds, want %d", len(all), len(want))
	}
}

// walkTombstones pages through ListTombstones and returns the concatenated
// segment ids plus per-page counts, asserting no id repeats.
func walkTombstones(t *testing.T, s *Store, source string, pageSize uint32) (ids []string, pageCounts []int) {
	t.Helper()
	ctx := context.Background()
	seen := map[string]bool{}
	token := ""
	for {
		resp, err := s.ListTombstones(ctx, &api.ListTombstonesRequest{
			SourceId: source, PageSize: pageSize, PageToken: token,
		})
		if err != nil {
			t.Fatal(err)
		}
		pageCounts = append(pageCounts, len(resp.Tombstones))
		for _, ts := range resp.Tombstones {
			if seen[ts.SegmentId] {
				t.Fatalf("tombstone %s returned twice across pages", ts.SegmentId)
			}
			seen[ts.SegmentId] = true
			ids = append(ids, ts.SegmentId)
		}
		if resp.NextPageToken == "" {
			break
		}
		token = resp.NextPageToken
	}
	return ids, pageCounts
}

func TestListTombstonesPagination(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	const source = "vps-01/api"
	s.policy = RetentionPolicy{DefaultDays: 30}

	old := time.Now().AddDate(0, 0, -40)
	want := map[string]bool{}
	for i := 0; i < 7; i++ {
		id := fmt.Sprintf("seg-%02d", i)
		seedSegment(t, s, id, source, uint64(i*10+1), uint64(i*10+10), old)
		want[id] = true
	}
	if _, err := s.EnforceRetention(ctx); err != nil {
		t.Fatal(err)
	}

	ids, counts := walkTombstones(t, s, source, 3)
	if fmt.Sprint(counts) != "[3 3 1]" {
		t.Fatalf("want page counts [3 3 1], got %v", counts)
	}
	if len(ids) != len(want) {
		t.Fatalf("want %d tombstones across pages, got %d", len(want), len(ids))
	}
	for _, id := range ids {
		if !want[id] {
			t.Fatalf("paged tombstone %s not in seeded set", id)
		}
	}

	all, allCounts := walkTombstones(t, s, source, 0)
	if len(allCounts) != 1 || allCounts[0] != len(want) {
		t.Fatalf("PageSize 0 should return all %d tombstones in one page, got counts %v", len(want), allCounts)
	}
	if len(all) != len(want) {
		t.Fatalf("PageSize 0 returned %d tombstones, want %d", len(all), len(want))
	}
}

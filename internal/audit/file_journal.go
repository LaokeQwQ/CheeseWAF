package audit

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// FileJournal is the durable Journal implementation for a single-node
// deployment. Each stream is an append-only JSONL file: one Commit per line,
// flushed and fsynced before Append returns, so a record never becomes visible
// to a reader without its checkpoint and outbox rows.
//
// Acknowledged outbox deliveries are recorded in a separate `<stream>.ack.json`
// sidecar that is rewritten atomically. The journal never rewrites the log
// itself, which is what makes the hash chain auditable after a crash.
type FileJournal struct {
	mu      sync.Mutex
	dir     string
	streams map[string]*fileStream
}

type fileStream struct {
	commits []Commit
	outbox  map[string]Delivery
	acked   map[string]bool
	file    *os.File
	size    int64
}

var _ Journal = (*FileJournal)(nil)

// OpenFileJournal opens (or creates) the journal directory. The directory is
// created with 0700 and every stream file is created with 0600.
func OpenFileJournal(dir string) (*FileJournal, error) {
	if strings.TrimSpace(dir) == "" || !filepath.IsAbs(dir) {
		return nil, fmt.Errorf("%w: journal directory must be an absolute path", ErrInvalidRecord)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("audit journal: create directory: %w", err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("audit journal: stat directory: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%w: journal path is not a directory", ErrInvalidRecord)
	}
	return &FileJournal{dir: dir, streams: make(map[string]*fileStream)}, nil
}

func (j *FileJournal) Durable() bool { return true }

func (j *FileJournal) Flush(ctx context.Context) error {
	if j == nil {
		return ErrInvalidRecord
	}
	if err := contextErr(ctx); err != nil {
		return err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	var firstErr error
	for _, stream := range j.streams {
		if stream.file == nil {
			continue
		}
		if err := stream.file.Sync(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// Close releases every open stream handle. Appends after Close fail.
func (j *FileJournal) Close() error {
	if j == nil {
		return nil
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	var firstErr error
	for _, stream := range j.streams {
		if stream.file == nil {
			continue
		}
		if err := stream.file.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		stream.file = nil
	}
	j.streams = make(map[string]*fileStream)
	return firstErr
}

func (j *FileJournal) Append(ctx context.Context, commit Commit) error {
	if j == nil {
		return ErrInvalidRecord
	}
	if err := contextErr(ctx); err != nil {
		return err
	}
	if err := validateCommit(commit); err != nil {
		return err
	}
	c := cloneCommit(commit)
	streamID := c.Record.Event.StreamID

	j.mu.Lock()
	defer j.mu.Unlock()
	state, err := j.loadStream(streamID)
	if err != nil {
		return err
	}
	if c.Record.Sequence <= uint64(len(state.commits)) {
		if commitEqual(state.commits[c.Record.Sequence-1], c) {
			return nil
		}
		return ErrReplayConflict
	}
	if c.Record.Sequence != uint64(len(state.commits))+1 {
		return ErrSequenceConflict
	}
	if len(state.commits) > 0 && c.Record.PreviousHash != state.commits[len(state.commits)-1].Record.Hash {
		return ErrSequenceConflict
	}
	for _, prior := range state.commits {
		if prior.Record.Event.EventID == c.Record.Event.EventID {
			return ErrReplayConflict
		}
	}
	for _, d := range c.Outbox {
		if prior, ok := state.outbox[d.DeliveryID]; ok && !deliveryEqual(prior, d) {
			return ErrOutboxConflict
		}
	}
	line, err := json.Marshal(c)
	if err != nil {
		return fmt.Errorf("audit journal: encode commit: %w", err)
	}
	if state.file == nil {
		file, openErr := os.OpenFile(j.streamPath(streamID), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if openErr != nil {
			return fmt.Errorf("audit journal: open stream: %w", openErr)
		}
		state.file = file
	}
	payload := append(line, '\n')
	if _, err := state.file.Write(payload); err != nil {
		return fmt.Errorf("audit journal: append: %w", err)
	}
	if err := state.file.Sync(); err != nil {
		return fmt.Errorf("audit journal: sync: %w", err)
	}
	state.size += int64(len(payload))
	state.commits = append(state.commits, c)
	for _, d := range c.Outbox {
		state.outbox[d.DeliveryID] = d
	}
	return nil
}

func (j *FileJournal) Records(ctx context.Context, stream string, after uint64, limit int) ([]Record, error) {
	if j == nil {
		return nil, ErrInvalidRecord
	}
	if err := contextErr(ctx); err != nil {
		return nil, err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	state, err := j.loadStream(stream)
	if err != nil {
		return nil, err
	}
	if err := verifyCommits(state.commits); err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = len(state.commits)
	}
	out := make([]Record, 0, limit)
	for _, c := range state.commits {
		if c.Record.Sequence > after {
			out = append(out, cloneRecord(c.Record))
			if len(out) >= limit {
				break
			}
		}
	}
	return out, nil
}

func (j *FileJournal) Last(ctx context.Context, stream string) (Record, error) {
	if j == nil {
		return Record{}, ErrInvalidRecord
	}
	if err := contextErr(ctx); err != nil {
		return Record{}, err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	state, err := j.loadStream(stream)
	if err != nil {
		return Record{}, err
	}
	if len(state.commits) == 0 {
		return Record{}, nil
	}
	if err := verifyCommits(state.commits); err != nil {
		return Record{}, err
	}
	return cloneRecord(state.commits[len(state.commits)-1].Record), nil
}

func (j *FileJournal) Checkpoint(ctx context.Context, stream string, sequence uint64) (*Checkpoint, error) {
	if j == nil {
		return nil, ErrCheckpointInvalid
	}
	if err := contextErr(ctx); err != nil {
		return nil, err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	state, err := j.loadStream(stream)
	if err != nil {
		return nil, err
	}
	if sequence == 0 || sequence > uint64(len(state.commits)) {
		return nil, nil
	}
	cp := state.commits[sequence-1].Checkpoint
	if cp == nil {
		return nil, nil
	}
	out := *cp
	out.Signature = append([]byte(nil), cp.Signature...)
	return &out, nil
}

func (j *FileJournal) PendingOutbox(ctx context.Context, stream string, limit int) ([]Delivery, error) {
	if j == nil {
		return nil, ErrOutboxInvalid
	}
	if err := contextErr(ctx); err != nil {
		return nil, err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	state, err := j.loadStream(stream)
	if err != nil {
		return nil, err
	}
	out := make([]Delivery, 0)
	for id, d := range state.outbox {
		if state.acked[id] || !d.DeliveredAt.IsZero() {
			continue
		}
		out = append(out, d)
	}
	sort.Slice(out, func(i, k int) bool {
		if out[i].Sequence == out[k].Sequence {
			return out[i].Target < out[k].Target
		}
		return out[i].Sequence < out[k].Sequence
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (j *FileJournal) AckOutbox(ctx context.Context, d Delivery) error {
	if j == nil {
		return ErrOutboxInvalid
	}
	if err := contextErr(ctx); err != nil {
		return err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	state, err := j.loadStream(d.StreamID)
	if err != nil {
		return err
	}
	prior, ok := state.outbox[d.DeliveryID]
	if !ok {
		return nil
	}
	if !deliveryIdentityEqual(prior, d) {
		return ErrOutboxConflict
	}
	deliveredAt := d.DeliveredAt
	if deliveredAt.IsZero() {
		deliveredAt = timeNowUTC()
	}
	prior.DeliveredAt = deliveredAt
	state.outbox[d.DeliveryID] = prior
	state.acked[d.DeliveryID] = true
	return j.persistAcks(d.StreamID, state)
}

func (j *FileJournal) Verify(ctx context.Context, stream string) error {
	if j == nil {
		return ErrInvalidRecord
	}
	if err := contextErr(ctx); err != nil {
		return err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	state, err := j.loadStream(stream)
	if err != nil {
		return err
	}
	return verifyCommits(state.commits)
}

func (j *FileJournal) streamPath(stream string) string {
	return filepath.Join(j.dir, stream+".jsonl")
}

func (j *FileJournal) ackPath(stream string) string {
	return filepath.Join(j.dir, stream+".ack.json")
}

func validStreamName(stream string) bool {
	if stream == "" || len(stream) > 128 {
		return false
	}
	for _, r := range stream {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
		default:
			return false
		}
	}
	return !strings.Contains(stream, "..") && stream != "." && stream != ".."
}

func (j *FileJournal) loadStream(stream string) (*fileStream, error) {
	if state, ok := j.streams[stream]; ok {
		return state, nil
	}
	if !validStreamName(stream) {
		return nil, fmt.Errorf("%w: invalid audit stream name", ErrInvalidRecord)
	}
	state := &fileStream{
		outbox: make(map[string]Delivery),
		acked:  make(map[string]bool),
	}
	file, err := os.Open(j.streamPath(stream))
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return nil, fmt.Errorf("audit journal: open stream: %w", err)
	default:
		defer file.Close()
		if err := readLog(file, state); err != nil {
			return nil, err
		}
	}
	if err := readAcks(j.ackPath(stream), state); err != nil {
		return nil, err
	}
	j.streams[stream] = state
	return state, nil
}

func readLog(file *os.File, state *fileStream) error {
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	line := 0
	for scanner.Scan() {
		line++
		raw := scanner.Bytes()
		if len(bytes.TrimSpace(raw)) == 0 {
			continue
		}
		var commit Commit
		if err := json.Unmarshal(raw, &commit); err != nil {
			return fmt.Errorf("%w: line %d: %v", ErrCorruptChain, line, err)
		}
		if err := validateCommit(commit); err != nil {
			return fmt.Errorf("%w: line %d: %v", ErrCorruptChain, line, err)
		}
		state.commits = append(state.commits, commit)
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("audit journal: read stream: %w", err)
	}
	if err := verifyCommits(state.commits); err != nil {
		return err
	}
	for _, commit := range state.commits {
		for _, d := range commit.Outbox {
			state.outbox[d.DeliveryID] = d
		}
	}
	return nil
}

func readAcks(path string, state *fileStream) error {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("audit journal: read ack file: %w", err)
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	var acked map[string]string
	if err := json.Unmarshal(raw, &acked); err != nil {
		return fmt.Errorf("%w: ack file: %v", ErrCorruptChain, err)
	}
	for id, at := range acked {
		state.acked[id] = true
		if d, ok := state.outbox[id]; ok {
			if parsed, perr := time.Parse(time.RFC3339, at); perr == nil {
				d.DeliveredAt = parsed
				state.outbox[id] = d
			}
		}
	}
	return nil
}

func (j *FileJournal) persistAcks(stream string, state *fileStream) error {
	acked := make(map[string]string, len(state.acked))
	for id := range state.acked {
		at := ""
		if d, ok := state.outbox[id]; ok && !d.DeliveredAt.IsZero() {
			at = d.DeliveredAt.UTC().Format(time.RFC3339)
		}
		acked[id] = at
	}
	raw, err := json.Marshal(acked)
	if err != nil {
		return fmt.Errorf("audit journal: encode ack file: %w", err)
	}
	return writeFileAtomic(j.ackPath(stream), raw)
}

func writeFileAtomic(path string, payload []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".ack-*.tmp")
	if err != nil {
		return fmt.Errorf("audit journal: create ack temp: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("audit journal: chmod ack temp: %w", err)
	}
	if _, err := tmp.Write(payload); err != nil {
		tmp.Close()
		return fmt.Errorf("audit journal: write ack temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("audit journal: sync ack temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("audit journal: close ack temp: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("audit journal: replace ack file: %w", err)
	}
	if dirFile, err := os.Open(dir); err == nil {
		_ = dirFile.Sync()
		_ = dirFile.Close()
	}
	return nil
}

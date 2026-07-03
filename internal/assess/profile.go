package assess

import (
	"embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

//go:embed profiles/*.json
var embeddedProfiles embed.FS

// FieldMap locates one normalized field in a source JSON object. Exactly one of
// Field (a dotted path) or Const (a fixed value) is used; Default supplies a
// value when the mapped field is absent; Layout names the timestamp format.
type FieldMap struct {
	Field   string `json:"field,omitempty"`
	Const   string `json:"const,omitempty"`
	Default string `json:"default,omitempty"`
	Layout  string `json:"layout,omitempty"`
}

// HeartbeatMatch marks a record as a heartbeat when the named field equals
// Equals, or when the event-type field is in Types.
type HeartbeatMatch struct {
	Field  string   `json:"field,omitempty"`
	Equals string   `json:"equals,omitempty"`
	Types  []string `json:"types,omitempty"`
}

// Profile maps a foreign JSON record shape onto normalized fields. A nil
// Sequence or Heartbeat is an honest declaration that the corresponding
// analysis is impossible on this export, not an omission.
type Profile struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	SourceID    *FieldMap       `json:"source_id"`
	Timestamp   *FieldMap       `json:"timestamp"`
	Sequence    *FieldMap       `json:"sequence"`
	Actor       *FieldMap       `json:"actor"`
	EventType   *FieldMap       `json:"event_type"`
	Heartbeat   *HeartbeatMatch `json:"heartbeat"`
}

// Capabilities derives the analyzer-selection capabilities from which mappings
// the profile declares.
func (p *Profile) Capabilities() Capabilities {
	return Capabilities{
		Sequenced:  p.Sequence != nil,
		Heartbeats: p.Heartbeat != nil,
		Typed:      p.EventType != nil,
		Actors:     p.Actor != nil,
	}
}

// timeLayouts maps profile layout tokens to Go reference layouts. "unix" and
// "unixms" are handled separately as numeric epochs.
var timeLayouts = map[string]string{
	"rfc3339":      time.RFC3339,
	"rfc3339nano":  time.RFC3339Nano,
	"":             time.RFC3339,
	"2006-01-02":   "2006-01-02",
	"datetime":     "2006-01-02 15:04:05",
	"datetime-utc": "2006-01-02 15:04:05 UTC",
}

// Validate checks the profile is usable before any input is read.
func (p *Profile) Validate() error {
	if strings.TrimSpace(p.Name) == "" {
		return fmt.Errorf("profile: name is required")
	}
	if p.Timestamp == nil || (p.Timestamp.Field == "" && p.Timestamp.Const == "") {
		return fmt.Errorf("profile %q: a timestamp mapping (field) is required", p.Name)
	}
	if l := p.Timestamp.Layout; l != "unix" && l != "unixms" {
		if _, ok := timeLayouts[l]; !ok {
			return fmt.Errorf("profile %q: unknown timestamp layout %q", p.Name, l)
		}
	}
	if p.SourceID != nil && p.SourceID.Field == "" && p.SourceID.Const == "" {
		return fmt.Errorf("profile %q: source_id mapping needs field or const", p.Name)
	}
	return nil
}

// parseTime parses a raw timestamp value per the profile layout.
func (fm *FieldMap) parseTime(v any) (time.Time, error) {
	switch fm.Layout {
	case "unix", "unixms":
		n, ok := toFloat(v)
		if !ok {
			return time.Time{}, fmt.Errorf("timestamp %v is not numeric for layout %s", v, fm.Layout)
		}
		if fm.Layout == "unixms" {
			return time.UnixMilli(int64(n)).UTC(), nil
		}
		return time.Unix(int64(n), 0).UTC(), nil
	default:
		s, ok := v.(string)
		if !ok {
			return time.Time{}, fmt.Errorf("timestamp %v is not a string", v)
		}
		t, err := time.Parse(timeLayouts[fm.Layout], s)
		if err != nil {
			return time.Time{}, err
		}
		return t.UTC(), nil
	}
}

func toFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	case string:
		f, err := strconv.ParseFloat(n, 64)
		return f, err == nil
	default:
		return 0, false
	}
}

// LoadProfile resolves a profile by explicit path, then user profile dir, then
// an embedded name. A value containing a path separator or ending in .json is
// treated as a file path.
func LoadProfile(nameOrPath string) (*Profile, error) {
	if nameOrPath == "" {
		return nil, fmt.Errorf("profile: empty name")
	}
	if strings.HasSuffix(nameOrPath, ".json") || strings.ContainsRune(nameOrPath, os.PathSeparator) {
		data, err := os.ReadFile(nameOrPath)
		if err != nil {
			return nil, err
		}
		return parseProfile(data)
	}
	if dir, err := os.UserConfigDir(); err == nil {
		p := filepath.Join(dir, "prooflog", "assess-profiles", nameOrPath+".json")
		if data, err := os.ReadFile(p); err == nil {
			return parseProfile(data)
		}
	}
	data, err := embeddedProfiles.ReadFile("profiles/" + nameOrPath + ".json")
	if err != nil {
		return nil, fmt.Errorf("unknown profile %q (not a file, not in user dir, not embedded)", nameOrPath)
	}
	return parseProfile(data)
}

func parseProfile(data []byte) (*Profile, error) {
	var p Profile
	if err := jsonUnmarshalStrict(data, &p); err != nil {
		return nil, fmt.Errorf("profile: %w", err)
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

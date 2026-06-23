package agenttax

import (
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
)

// confidenceOrder ranks bands for "highest" / fail-on comparisons.
var confidenceOrder = map[string]int{"high": 0, "medium": 1, "low": 2, "none": 3}

// CategoryMatch is one matched taxonomy category for a finding.
type CategoryMatch struct {
	CategoryID     string   `json:"category_id"`
	Label          string   `json:"label"`
	Reference      string   `json:"reference"`
	Confidence     float64  `json:"confidence"`
	Band           string   `json:"band"`
	MatchedSignals []string `json:"matched_signals"`
	Mitigation     string   `json:"mitigation"`
}

// Classification is one finding plus its matches.
type Classification struct {
	ID      string          `json:"id"`
	Title   string          `json:"title"`
	Text    string          `json:"text"`
	TopBand string          `json:"top_band"`
	Matches []CategoryMatch `json:"matches"`
}

// Summary aggregates a report.
type Summary struct {
	Findings          int            `json:"findings"`
	Classified        int            `json:"classified"`
	Unclassified      int            `json:"unclassified"`
	ByCategory        map[string]int `json:"by_category"`
	HighestConfidence string         `json:"highest_confidence"`
}

// Report is the full classification result.
type Report struct {
	Tool            string           `json:"tool"`
	Version         string           `json:"version"`
	Source          string           `json:"source"`
	Summary         Summary          `json:"summary"`
	Classifications []Classification `json:"classifications"`
}

// Finding is a normalised input record.
type Finding struct {
	ID    string
	Title string
	Text  string
}

func band(conf float64) string {
	switch {
	case conf >= bandHigh:
		return "high"
	case conf >= bandMedium:
		return "medium"
	case conf > 0:
		return "low"
	default:
		return "none"
	}
}

func round3(f float64) float64 { return math.Round(f*1000) / 1000 }

// ClassifyText classifies a single text blob against every taxonomy category.
func ClassifyText(text string, minConfidence float64) []CategoryMatch {
	matches := []CategoryMatch{}
	for i := range Taxonomy {
		cat := &Taxonomy[i]
		raw := 0.0
		hits := []string{}
		for j := range cat.Signals {
			if cat.Signals[j].compiled().MatchString(text) {
				raw += cat.Signals[j].Weight
				hits = append(hits, cat.Signals[j].Pattern)
			}
		}
		if raw <= 0 {
			continue
		}
		conf := round3(math.Min(1.0, raw/saturation))
		if conf < minConfidence {
			continue
		}
		matches = append(matches, CategoryMatch{
			CategoryID:     cat.ID,
			Label:          cat.Label,
			Reference:      cat.Reference,
			Confidence:     conf,
			Band:           band(conf),
			MatchedSignals: hits,
			Mitigation:     cat.Mitigation,
		})
	}
	sort.SliceStable(matches, func(a, b int) bool {
		if matches[a].Confidence != matches[b].Confidence {
			return matches[a].Confidence > matches[b].Confidence
		}
		return matches[a].CategoryID < matches[b].CategoryID
	})
	return matches
}

var fieldKeys = []string{"title", "name", "description", "text", "message", "detail", "summary", "observation"}

func asString(v interface{}) string {
	if v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return t
	case float64:
		if t == math.Trunc(t) {
			return fmt.Sprintf("%d", int64(t))
		}
		return fmt.Sprintf("%v", t)
	default:
		b, _ := json.Marshal(v)
		return string(b)
	}
}

// NormalizeFindings accepts a top-level array or an object with a "findings" array.
func NormalizeFindings(data interface{}) ([]Finding, error) {
	var items []interface{}
	switch d := data.(type) {
	case map[string]interface{}:
		if f, ok := d["findings"]; ok {
			arr, ok2 := f.([]interface{})
			if !ok2 {
				return nil, fmt.Errorf("`findings` must be an array")
			}
			items = arr
		} else {
			items = []interface{}{d}
		}
	case []interface{}:
		items = d
	default:
		return nil, fmt.Errorf("findings root must be a JSON object or array")
	}

	out := []Finding{}
	for idx, item := range items {
		switch it := item.(type) {
		case string:
			out = append(out, Finding{ID: fmt.Sprintf("F%d", idx+1), Text: it})
		case map[string]interface{}:
			fid := asString(it["id"])
			if fid == "" {
				fid = asString(it["rule"])
			}
			if fid == "" {
				fid = fmt.Sprintf("F%d", idx+1)
			}
			title := asString(it["title"])
			if title == "" {
				title = asString(it["name"])
			}
			parts := []string{}
			for _, k := range fieldKeys {
				if s := asString(it[k]); s != "" {
					parts = append(parts, s)
				}
			}
			text := strings.TrimSpace(strings.Join(parts, " "))
			if text == "" {
				b, _ := json.Marshal(it)
				text = string(b)
			}
			out = append(out, Finding{ID: fid, Title: title, Text: text})
		default:
			return nil, fmt.Errorf("finding #%d must be an object or string", idx)
		}
	}
	return out, nil
}

var paraSplit = regexp.MustCompile(`\n\s*\n|\r?\n`)

// FindingsFromText splits a free-text blob into one finding per paragraph/line.
func FindingsFromText(text string) []Finding {
	chunks := []string{}
	for _, c := range paraSplit.Split(text, -1) {
		if t := strings.TrimSpace(c); t != "" {
			chunks = append(chunks, t)
		}
	}
	if len(chunks) == 0 {
		if t := strings.TrimSpace(text); t != "" {
			chunks = []string{t}
		}
	}
	out := []Finding{}
	for i, c := range chunks {
		out = append(out, Finding{ID: fmt.Sprintf("T%d", i+1), Text: c})
	}
	return out
}

func minBand(bands []string) string {
	if len(bands) == 0 {
		return "none"
	}
	best := bands[0]
	for _, b := range bands[1:] {
		if confidenceOrder[b] < confidenceOrder[best] {
			best = b
		}
	}
	return best
}

// ClassifyFindings classifies a list of findings into a Report.
func ClassifyFindings(findings []Finding, source string, minConfidence float64) Report {
	cls := []Classification{}
	byCat := map[string]int{}
	for _, c := range Taxonomy {
		byCat[c.ID] = 0
	}
	unclassified := 0
	topBands := []string{}
	for _, f := range findings {
		m := ClassifyText(f.Text, minConfidence)
		bands := []string{}
		for _, x := range m {
			byCat[x.CategoryID]++
			bands = append(bands, x.Band)
		}
		tb := minBand(bands)
		if len(m) == 0 {
			unclassified++
		}
		topBands = append(topBands, tb)
		cls = append(cls, Classification{ID: f.ID, Title: f.Title, Text: f.Text, TopBand: tb, Matches: m})
	}
	return Report{
		Tool:    ToolName,
		Version: ToolVersion,
		Source:  source,
		Summary: Summary{
			Findings:          len(cls),
			Classified:        len(cls) - unclassified,
			Unclassified:      unclassified,
			ByCategory:        byCat,
			HighestConfidence: minBand(topBands),
		},
		Classifications: cls,
	}
}

// TaxonomyEntry is the doc/introspection view of a category.
type TaxonomyEntry struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	Reference   string `json:"reference"`
	Description string `json:"description"`
	Mitigation  string `json:"mitigation"`
	SignalCount int    `json:"signal_count"`
}

// GetTaxonomy returns the taxonomy as plain entries.
func GetTaxonomy() []TaxonomyEntry {
	out := []TaxonomyEntry{}
	for _, c := range Taxonomy {
		out = append(out, TaxonomyEntry{
			ID: c.ID, Label: c.Label, Reference: c.Reference,
			Description: c.Description, Mitigation: c.Mitigation, SignalCount: len(c.Signals),
		})
	}
	return out
}

// FailTriggered reports whether any match reaches the fail-on band.
func FailTriggered(r Report, failOn string) bool {
	if failOn == "none" {
		return false
	}
	threshold := confidenceOrder[failOn]
	for _, cl := range r.Classifications {
		for _, m := range cl.Matches {
			if confidenceOrder[m.Band] <= threshold {
				return true
			}
		}
	}
	return false
}

// CSVColumns is the stable CSV header order.
var CSVColumns = []string{
	"finding_id", "title", "category_id", "category_label", "reference",
	"confidence", "band", "matched_signals", "mitigation", "text",
}

// Command agenttax — Go port CLI. Mirrors `agenttax classify` + `taxonomy`.
// Passive, offline, no network. Standard library only.
package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"

	agenttax "github.com/cognis-digital/agenttax/ports/go"
)

var bandLabel = map[string]string{"high": "HIGH", "medium": "MED ", "low": "LOW ", "none": "----"}

func renderTable(r agenttax.Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "AGENTTAX — AI-agent threat taxonomy mapping  (source: %s)\n", r.Source)
	b.WriteString(strings.Repeat("=", 74) + "\n")
	if len(r.Classifications) == 0 {
		b.WriteString("No findings to classify.\n")
		return b.String()
	}
	for _, cl := range r.Classifications {
		head := cl.ID
		if cl.Title != "" {
			head += ": " + cl.Title
		}
		b.WriteString(head + "\n")
		snip := cl.Text
		if len(snip) > 100 {
			snip = snip[:97] + "..."
		}
		fmt.Fprintf(&b, "    %q\n", snip)
		if len(cl.Matches) == 0 {
			b.WriteString("    [----] no taxonomy category matched (review manually)\n")
		}
		for _, m := range cl.Matches {
			lbl := bandLabel[m.Band]
			if lbl == "" {
				lbl = strings.ToUpper(m.Band)
			}
			fmt.Fprintf(&b, "    [%s] %s  (conf %.2f, %s)\n", lbl, m.Label, m.Confidence, m.Reference)
			fmt.Fprintf(&b, "           mitigation: %s\n", m.Mitigation)
		}
		b.WriteString("\n")
	}
	s := r.Summary
	b.WriteString(strings.Repeat("-", 74) + "\n")
	bits := []string{}
	for _, c := range agenttax.Taxonomy {
		if n := s.ByCategory[c.ID]; n > 0 {
			bits = append(bits, fmt.Sprintf("%s=%d", strings.ToLower(strings.Split(c.ID, "_")[0]), n))
		}
	}
	cat := "none"
	if len(bits) > 0 {
		cat = strings.Join(bits, ", ")
	}
	fmt.Fprintf(&b, "findings=%d  classified=%d  unclassified=%d\n", s.Findings, s.Classified, s.Unclassified)
	fmt.Fprintf(&b, "category hits: %s\n", cat)
	fmt.Fprintf(&b, "highest confidence: %s", s.HighestConfidence)
	return b.String()
}

func renderTaxonomy() string {
	var b strings.Builder
	b.WriteString("AGENTTAX — Microsoft AI-agent threat taxonomy (7 categories)\n")
	b.WriteString(strings.Repeat("=", 74) + "\n")
	for _, c := range agenttax.GetTaxonomy() {
		fmt.Fprintf(&b, "%s  [%s]\n", c.ID, c.Reference)
		fmt.Fprintf(&b, "    %s\n", c.Label)
		fmt.Fprintf(&b, "    %s\n", c.Description)
		fmt.Fprintf(&b, "    mitigation: %s\n", c.Mitigation)
		fmt.Fprintf(&b, "    signals: %d\n\n", c.SignalCount)
	}
	return strings.TrimRight(b.String(), "\n")
}

func toCSV(r agenttax.Report) string {
	var sb strings.Builder
	w := csv.NewWriter(&sb)
	_ = w.Write(agenttax.CSVColumns)
	for _, cl := range r.Classifications {
		if len(cl.Matches) == 0 {
			_ = w.Write([]string{cl.ID, cl.Title, "", "", "", "", "none", "", "", cl.Text})
			continue
		}
		for _, m := range cl.Matches {
			_ = w.Write([]string{
				cl.ID, cl.Title, m.CategoryID, m.Label, m.Reference,
				strconv.FormatFloat(m.Confidence, 'f', 3, 64), m.Band,
				strings.Join(m.MatchedSignals, "; "), m.Mitigation, cl.Text,
			})
		}
	}
	w.Flush()
	return strings.TrimRight(sb.String(), "\n")
}

func toSARIF(r agenttax.Report) map[string]interface{} {
	ruleIndex := map[string]int{}
	rules := []map[string]interface{}{}
	for i, c := range agenttax.Taxonomy {
		ruleIndex[c.ID] = i
		rules = append(rules, map[string]interface{}{
			"id":               c.ID,
			"name":             c.Label,
			"shortDescription": map[string]string{"text": c.Label},
			"fullDescription":  map[string]string{"text": c.Description},
			"helpUri":          "https://cognis.digital/agenttax",
			"help":             map[string]string{"text": "Mitigation: " + c.Mitigation},
			"properties": map[string]interface{}{
				"reference": c.Reference,
				"tags":      []string{"ai-security", "agentic", "microsoft-taxonomy"},
			},
		})
	}
	levels := map[string]string{"high": "error", "medium": "warning", "low": "note", "none": "none"}
	results := []map[string]interface{}{}
	for _, cl := range r.Classifications {
		for _, m := range cl.Matches {
			lvl := levels[m.Band]
			if lvl == "" {
				lvl = "note"
			}
			results = append(results, map[string]interface{}{
				"ruleId":    m.CategoryID,
				"ruleIndex": ruleIndex[m.CategoryID],
				"level":     lvl,
				"message": map[string]string{"text": fmt.Sprintf(
					"[%s] %s: confidence %.2f (%s). Mitigation: %s", m.Label, cl.ID, m.Confidence, m.Band, m.Mitigation)},
				"properties": map[string]interface{}{
					"findingId": cl.ID, "confidence": m.Confidence, "band": m.Band, "matchedSignals": m.MatchedSignals,
				},
				"locations": []map[string]interface{}{{
					"physicalLocation": map[string]interface{}{
						"artifactLocation": map[string]string{"uri": r.Source},
						"logicalLocations": []map[string]string{{"name": cl.ID}},
					},
				}},
			})
		}
	}
	return map[string]interface{}{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": []map[string]interface{}{{
			"tool": map[string]interface{}{"driver": map[string]interface{}{
				"name": agenttax.ToolName, "version": agenttax.ToolVersion,
				"informationUri": "https://cognis.digital/agenttax", "rules": rules,
			}},
			"results": results,
		}},
	}
}

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(argv []string) int {
	for _, a := range argv {
		if a == "--version" {
			fmt.Printf("%s %s\n", agenttax.ToolName, agenttax.ToolVersion)
			return 0
		}
	}
	if len(argv) == 0 {
		fmt.Fprintf(os.Stderr, "usage: %s {classify,taxonomy} [...]\n", agenttax.ToolName)
		return 2
	}
	cmd := argv[0]
	if cmd == "taxonomy" {
		fmt.Println(renderTaxonomy())
		return 0
	}
	if cmd != "classify" {
		fmt.Fprintf(os.Stderr, "usage: %s {classify,taxonomy} [...]\n", agenttax.ToolName)
		return 2
	}

	var path, text, format, out, failOn string
	format = "table"
	failOn = "none"
	minConf := 0.0
	for i := 1; i < len(argv); i++ {
		t := argv[i]
		switch {
		case t == "--text" && i+1 < len(argv):
			i++
			text = argv[i]
		case t == "--format" && i+1 < len(argv):
			i++
			format = argv[i]
		case t == "--min-confidence" && i+1 < len(argv):
			i++
			minConf, _ = strconv.ParseFloat(argv[i], 64)
		case t == "--fail-on" && i+1 < len(argv):
			i++
			failOn = argv[i]
		case t == "--out" && i+1 < len(argv):
			i++
			out = argv[i]
		case !strings.HasPrefix(t, "--") && path == "":
			path = t
		}
	}

	var findings []agenttax.Finding
	var source string
	if text != "" {
		findings = agenttax.FindingsFromText(text)
		source = "<text>"
	} else if path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 2
		}
		var data interface{}
		if err := json.Unmarshal(raw, &data); err != nil {
			fmt.Fprintf(os.Stderr, "error: invalid JSON in %s: %v\n", path, err)
			return 2
		}
		findings, err = agenttax.NormalizeFindings(data)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 2
		}
		source = path
	} else {
		fmt.Fprintln(os.Stderr, "error: provide a findings file or --text")
		return 2
	}

	mc := math.Max(0.0, math.Min(1.0, minConf))
	report := agenttax.ClassifyFindings(findings, source, mc)

	var output string
	switch format {
	case "json":
		b, _ := json.MarshalIndent(report, "", "  ")
		output = string(b)
	case "sarif":
		b, _ := json.MarshalIndent(toSARIF(report), "", "  ")
		output = string(b)
	case "csv":
		output = toCSV(report)
	default:
		output = renderTable(report)
	}

	if out != "" {
		if err := os.WriteFile(out, []byte(output+"\n"), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 2
		}
	} else {
		fmt.Println(output)
	}

	if agenttax.FailTriggered(report, failOn) {
		return 1
	}
	return 0
}

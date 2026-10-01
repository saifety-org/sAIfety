package report

import (
	"encoding/json"
	"io"

	"github.com/alexandr-mironov/saifety/internal/scan"
)

// SARIF writes the summary as SARIF 2.1.0, the standard static-analysis
// format that GitHub code scanning, GitLab and other CI systems ingest.
func SARIF(w io.Writer, s *Summary) error {
	rules := map[string]sarifRule{}
	var results []sarifResult
	for _, v := range s.Verdicts {
		for _, f := range v.Findings {
			id := string(f.Category)
			if _, ok := rules[id]; !ok {
				rules[id] = sarifRule{ID: id, Name: id, ShortDescription: sarifText{Text: id}}
			}
			line := f.Line
			if line < 1 {
				line = 1
			}
			results = append(results, sarifResult{
				RuleID:  id,
				Level:   sarifLevel(f.Level),
				Message: sarifText{Text: f.Message + " (" + f.Detector + ", confidence " + trim(f.Confidence) + ", action " + v.Action.String() + ")"},
				Locations: []sarifLocation{{
					PhysicalLocation: sarifPhysical{
						ArtifactLocation: sarifArtifact{URI: v.Source},
						Region:           sarifRegion{StartLine: line},
					},
				}},
			})
		}
	}
	var ruleList []sarifRule
	for _, r := range rules {
		ruleList = append(ruleList, r)
	}
	doc := sarifDoc{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "sAIfety",
				InformationURI: "https://github.com/alexandr-mironov/saifety",
				Rules:          ruleList,
			}},
			Results: results,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

func sarifLevel(l scan.Level) string {
	switch l {
	case scan.LevelCritical:
		return "error"
	case scan.LevelMedium:
		return "warning"
	default:
		return "note"
	}
}

func trim(f float64) string {
	return string([]byte{byte('0' + int(f*10)/10%10), '.', byte('0' + int(f*10)%10)})
}

type sarifDoc struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}
type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}
type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}
type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}
type sarifRule struct {
	ID               string    `json:"id"`
	Name             string    `json:"name"`
	ShortDescription sarifText `json:"shortDescription"`
}
type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifText       `json:"message"`
	Locations []sarifLocation `json:"locations"`
}
type sarifText struct {
	Text string `json:"text"`
}
type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}
type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           sarifRegion   `json:"region"`
}
type sarifArtifact struct {
	URI string `json:"uri"`
}
type sarifRegion struct {
	StartLine int `json:"startLine"`
}

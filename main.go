package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

type cweField []string

func (c *cweField) UnmarshalJSON(data []byte) error {
	var arr []string
	if err := json.Unmarshal(data, &arr); err == nil {
		*c = arr
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		if s == "" {
			*c = nil
		} else {
			*c = []string{s}
		}
		return nil
	}
	*c = nil
	return nil
}

type advisory struct {
	ID                 int      `json:"id"`
	ModuleName         string   `json:"module_name"`
	Title              string   `json:"title"`
	Overview           string   `json:"overview"`
	Severity           string   `json:"severity"`
	Recommendation     string   `json:"recommendation"`
	VulnerableVersions string   `json:"vulnerable_versions"`
	GithubAdvisoryID   string   `json:"github_advisory_id"`
	CVEs               []string `json:"cves"`
	CWE                cweField `json:"cwe"`
	Findings           []struct {
		Paths []string `json:"paths"`
	} `json:"findings"`
}

type input struct {
	Advisories map[string]advisory `json:"advisories"`
}

type identifier struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	Value string `json:"value"`
	URL   string `json:"url"`
}

type instance struct {
	Method string `json:"method"`
}

type link struct {
	URL string `json:"url"`
}

type scanner struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type pkg struct {
	Name string `json:"name"`
}

type dependency struct {
	Package pkg    `json:"package"`
	Version string `json:"version"`
}

type location struct {
	File       string     `json:"file"`
	Dependency dependency `json:"dependency"`
}

type vulnerability struct {
	Tool        string       `json:"tool"`
	Category    string       `json:"category"`
	Name        string       `json:"name"`
	Namespace   string       `json:"namespace"`
	Message     string       `json:"message"`
	CVE         string       `json:"cve"`
	Description string       `json:"description"`
	Severity    string       `json:"severity"`
	FixedBy     string       `json:"fixedby"`
	Confidence  string       `json:"confidence"`
	Scanner     scanner      `json:"scanner"`
	Location    location     `json:"location"`
	Identifiers []identifier `json:"identifiers"`
	Solution    string       `json:"solution"`
	Instances   []instance   `json:"instances"`
	Links       []link       `json:"links"`
}

type report struct {
	Version         string          `json:"version"`
	Vulnerabilities []vulnerability `json:"vulnerabilities"`
	Remediations    []any           `json:"remediations"`
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func getSeverity(s string) string {
	allowed := map[string]bool{
		"Info": true, "Unknown": true, "Low": true,
		"Medium": true, "High": true, "Critical": true,
	}
	c := capitalize(s)
	if allowed[c] {
		return c
	}
	if c == "Moderate" {
		return "Medium"
	}
	return "Unknown"
}

func getCWEID(s string) string {
	return strings.Replace(s, "CWE-", "", 1)
}

func convert(in input) report {
	r := report{
		Version:         "2.0",
		Vulnerabilities: []vulnerability{},
		Remediations:    []any{},
	}

	for _, a := range in.Advisories {
		cweRaw := "N/A"
		if len(a.CWE) > 0 {
			cweRaw = a.CWE[0]
		}
		cweID := getCWEID(cweRaw)

		cve := "N/A"
		if a.GithubAdvisoryID != "" {
			cve = "GHSA-" + a.GithubAdvisoryID
		}

		idents := []identifier{}
		if a.GithubAdvisoryID != "" {
			idents = append(idents, identifier{
				Type:  "ghsa_id",
				Name:  a.GithubAdvisoryID,
				Value: a.GithubAdvisoryID,
				URL:   "https://github.com/advisories/" + a.GithubAdvisoryID,
			})
		}
		if len(a.CVEs) > 0 {
			idents = append(idents, identifier{
				Type:  "cve_id",
				Name:  a.CVEs[0],
				Value: a.CVEs[0],
				URL:   "https://nvd.nist.gov/vuln/detail/" + a.CVEs[0],
			})
		}
		if len(a.CWE) > 0 {
			idents = append(idents, identifier{
				Type:  "cwe_id",
				Name:  a.CWE[0],
				Value: a.CWE[0],
				URL:   fmt.Sprintf("https://cwe.mitre.org/data/definitions/%s.html", cweID),
			})
		}

		instances := []instance{}
		if len(a.Findings) > 0 {
			for _, p := range a.Findings[0].Paths {
				instances = append(instances, instance{Method: p})
			}
		}

		r.Vulnerabilities = append(r.Vulnerabilities, vulnerability{
			Tool:        "pnpm_audit",
			Category:    "dependency_scanning",
			Name:        a.ModuleName,
			Namespace:   a.ModuleName,
			Message:     a.Title,
			CVE:         cve,
			Description: a.Overview,
			Severity:    getSeverity(a.Severity),
			FixedBy:     a.Recommendation,
			Confidence:  "High",
			Scanner:     scanner{ID: "pnpm_audit_advisories", Name: "PNPM Audit"},
			Location: location{
				File: "pnpm-lock.yaml",
				Dependency: dependency{
					Package: pkg{Name: a.ModuleName},
					Version: a.VulnerableVersions,
				},
			},
			Identifiers: idents,
			Solution:    a.Recommendation,
			Instances:   instances,
			Links:       []link{{URL: fmt.Sprintf("https://npmjs.com/advisories/%d", a.ID)}},
		})
	}

	return r
}

func main() {
	out := flag.String("o", "gl-dependency-scanning-report.json", "output filename")
	flag.StringVar(out, "out", *out, "output filename")
	flag.Parse()

	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	var in input
	if err := json.Unmarshal(data, &in); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	r := convert(in)
	encoded, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	if err := os.WriteFile(*out, encoded, 0644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	fmt.Printf("The file was saved as %s!\n", *out)
}

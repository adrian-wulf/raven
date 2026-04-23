package deps

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	toml "github.com/pelletier/go-toml/v2"
)

const osvAPIURL = "https://api.osv.dev/v1/query"

// Vulnerability represents a dependency vulnerability
type Vulnerability struct {
	ID          string   `json:"id"`
	Summary     string   `json:"summary"`
	Details     string   `json:"details"`
	Severity    string   `json:"severity"`
	Package     string   `json:"package"`
	Version     string   `json:"version"`
	FixedVersion string  `json:"fixed_version"`
	References  []string `json:"references"`
}

// Package represents a dependency package
type Package struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"`
}

// Scanner scans dependencies for known vulnerabilities
type Scanner struct {
	offline bool
}

// NewScanner creates a new dependency scanner
func NewScanner() *Scanner {
	return &Scanner{
		offline: os.Getenv("RAVEN_OFFLINE") == "true",
	}
}

// Scan scans project dependencies for vulnerabilities
func (s *Scanner) Scan(root string) ([]Vulnerability, error) {
	if s.offline {
		return nil, fmt.Errorf("offline mode: dependency scanning requires internet")
	}

	var allVulns []Vulnerability

	// Scan package.json
	if vulns, err := s.scanPackageJSON(root); err == nil {
		allVulns = append(allVulns, vulns...)
	}

	// Scan requirements.txt
	if vulns, err := s.scanRequirementsTXT(root); err == nil {
		allVulns = append(allVulns, vulns...)
	}

	// Scan go.mod
	if vulns, err := s.scanGoMod(root); err == nil {
		allVulns = append(allVulns, vulns...)
	}

	// Scan Cargo.toml
	if vulns, err := s.scanCargoToml(root); err == nil {
		allVulns = append(allVulns, vulns...)
	}

	// Scan composer.json
	if vulns, err := s.scanComposerJSON(root); err == nil {
		allVulns = append(allVulns, vulns...)
	}

	return allVulns, nil
}

func (s *Scanner) scanPackageJSON(root string) ([]Vulnerability, error) {
	path := filepath.Join(root, "package.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var pkg struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil, err
	}

	allDeps := make(map[string]string)
	for k, v := range pkg.Dependencies {
		allDeps[k] = v
	}
	for k, v := range pkg.DevDependencies {
		allDeps[k] = v
	}

	var vulns []Vulnerability
	for name, version := range allDeps {
		// Clean version prefix
		version = strings.TrimPrefix(version, "^")
		version = strings.TrimPrefix(version, "~")
		version = strings.TrimPrefix(version, ">=")
		version = strings.TrimPrefix(version, ">")
		version = strings.TrimSpace(version)

		if v, err := s.queryOSV(name, version, "npm"); err == nil {
			vulns = append(vulns, v...)
		}
	}

	return vulns, nil
}

func (s *Scanner) scanRequirementsTXT(root string) ([]Vulnerability, error) {
	path := filepath.Join(root, "requirements.txt")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var vulns []Vulnerability
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}

		// Parse package==version or package>=version
		parts := strings.Split(line, "==")
		if len(parts) == 2 {
			name := strings.TrimSpace(parts[0])
			version := strings.TrimSpace(parts[1])
			if v, err := s.queryOSV(name, version, "PyPI"); err == nil {
				vulns = append(vulns, v...)
			}
			continue
		}

		parts = strings.Split(line, ">=")
		if len(parts) == 2 {
			name := strings.TrimSpace(parts[0])
			version := strings.TrimSpace(parts[1])
			if v, err := s.queryOSV(name, version, "PyPI"); err == nil {
				vulns = append(vulns, v...)
			}
		}
	}

	return vulns, nil
}

func (s *Scanner) scanGoMod(root string) ([]Vulnerability, error) {
	path := filepath.Join(root, "go.mod")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var vulns []Vulnerability
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "require ") {
			continue
		}

		// Parse: require github.com/foo/bar v1.2.3
		parts := strings.Fields(line)
		if len(parts) >= 3 {
			name := parts[1]
			version := strings.TrimPrefix(parts[2], "v")
			if v, err := s.queryOSV(name, version, "Go"); err == nil {
				vulns = append(vulns, v...)
			}
		}
	}

	return vulns, nil
}

func (s *Scanner) scanCargoToml(root string) ([]Vulnerability, error) {
	path := filepath.Join(root, "Cargo.toml")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cargo struct {
		Dependencies map[string]interface{} `toml:"dependencies"`
	}
	if err := toml.Unmarshal(data, &cargo); err != nil {
		return nil, err
	}

	var vulns []Vulnerability
	for name, version := range cargo.Dependencies {
		var verStr string
		switch v := version.(type) {
		case string:
			verStr = v
		case map[string]interface{}:
			if v, ok := v["version"].(string); ok {
				verStr = v
			}
		}
		if verStr != "" {
			if v, err := s.queryOSV(name, verStr, "crates.io"); err == nil {
				vulns = append(vulns, v...)
			}
		}
	}

	return vulns, nil
}

func (s *Scanner) scanComposerJSON(root string) ([]Vulnerability, error) {
	path := filepath.Join(root, "composer.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var composer struct {
		Require map[string]string `json:"require"`
	}
	if err := json.Unmarshal(data, &composer); err != nil {
		return nil, err
	}

	var vulns []Vulnerability
	for name, version := range composer.Require {
		version = strings.TrimPrefix(version, "^")
		version = strings.TrimPrefix(version, "~")
		if v, err := s.queryOSV(name, version, "Packagist"); err == nil {
			vulns = append(vulns, v...)
		}
	}

	return vulns, nil
}

func (s *Scanner) queryOSV(name, version, ecosystem string) ([]Vulnerability, error) {
	reqBody := map[string]interface{}{
		"package": map[string]string{
			"name":      name,
			"ecosystem": ecosystem,
		},
		"version": version,
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", osvAPIURL, bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("OSV API error: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result struct {
		Vulns []struct {
			ID       string `json:"id"`
			Summary  string `json:"summary"`
			Details  string `json:"details"`
			Severity []struct {
				Type  string `json:"type"`
				Score string `json:"score"`
			} `json:"severity"`
			Affected []struct {
				Package struct {
					Name      string `json:"name"`
					Ecosystem string `json:"ecosystem"`
				} `json:"package"`
				Ranges []struct {
					Type   string `json:"type"`
					Events []struct {
						Introduced string `json:"introduced"`
						Fixed      string `json:"fixed"`
					} `json:"events"`
				} `json:"ranges"`
			} `json:"affected"`
			References []struct {
				Type string `json:"type"`
				URL  string `json:"url"`
			} `json:"references"`
		} `json:"vulns"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	var vulns []Vulnerability
	for _, v := range result.Vulns {
		severity := "unknown"
		if len(v.Severity) > 0 {
			severity = v.Severity[0].Score
		}

		fixedVersion := ""
		if len(v.Affected) > 0 && len(v.Affected[0].Ranges) > 0 {
			for _, event := range v.Affected[0].Ranges[0].Events {
				if event.Fixed != "" {
					fixedVersion = event.Fixed
					break
				}
			}
		}

		var refs []string
		for _, r := range v.References {
			refs = append(refs, r.URL)
		}

		vulns = append(vulns, Vulnerability{
			ID:           v.ID,
			Summary:      v.Summary,
			Details:      v.Details,
			Severity:     severity,
			Package:      name,
			Version:      version,
			FixedVersion: fixedVersion,
			References:   refs,
		})
	}

	return vulns, nil
}

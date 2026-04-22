package framework

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Framework represents a detected web framework
type Framework struct {
	Name       string   `json:"name"`
	Version    string   `json:"version"`
	Language   string   `json:"language"`
	Confidence float64  `json:"confidence"`
	Files      []string `json:"files"`
}

// Detector detects frameworks from project files
type Detector struct {
	root string
}

// NewDetector creates a new framework detector
func NewDetector(root string) *Detector {
	return &Detector{root: root}
}

// Detect scans the project and returns detected frameworks
func (d *Detector) Detect() ([]Framework, error) {
	var frameworks []Framework

	// Check package.json (Node.js)
	if fw := d.detectNodeJS(); fw != nil {
		frameworks = append(frameworks, fw...)
	}

	// Check requirements.txt / pyproject.toml (Python)
	if fw := d.detectPython(); fw != nil {
		frameworks = append(frameworks, fw...)
	}

	// Check go.mod (Go)
	if fw := d.detectGo(); fw != nil {
		frameworks = append(frameworks, fw...)
	}

	// Check composer.json (PHP)
	if fw := d.detectPHP(); fw != nil {
		frameworks = append(frameworks, fw...)
	}

	// Check Cargo.toml (Rust)
	if fw := d.detectRust(); fw != nil {
		frameworks = append(frameworks, fw...)
	}

	return frameworks, nil
}

func (d *Detector) detectNodeJS() []Framework {
	var frameworks []Framework

	packageJSONPath := filepath.Join(d.root, "package.json")
	data, err := os.ReadFile(packageJSONPath)
	if err != nil {
		return nil
	}

	var pkg struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil
	}

	allDeps := mergeMaps(pkg.Dependencies, pkg.DevDependencies)

	// Express
	if version, ok := allDeps["express"]; ok {
		frameworks = append(frameworks, Framework{
			Name:       "express",
			Version:    version,
			Language:   "javascript",
			Confidence: 1.0,
			Files:      []string{packageJSONPath},
		})
	}

	// Next.js
	if version, ok := allDeps["next"]; ok {
		frameworks = append(frameworks, Framework{
			Name:       "nextjs",
			Version:    version,
			Language:   "javascript",
			Confidence: 1.0,
			Files:      []string{packageJSONPath},
		})
	}

	// React
	if version, ok := allDeps["react"]; ok {
		frameworks = append(frameworks, Framework{
			Name:       "react",
			Version:    version,
			Language:   "javascript",
			Confidence: 0.9,
			Files:      []string{packageJSONPath},
		})
	}

	// Vue
	if version, ok := allDeps["vue"]; ok {
		frameworks = append(frameworks, Framework{
			Name:       "vue",
			Version:    version,
			Language:   "javascript",
			Confidence: 1.0,
			Files:      []string{packageJSONPath},
		})
	}

	// Fastify
	if version, ok := allDeps["fastify"]; ok {
		frameworks = append(frameworks, Framework{
			Name:       "fastify",
			Version:    version,
			Language:   "javascript",
			Confidence: 1.0,
			Files:      []string{packageJSONPath},
		})
	}

	// Koa
	if version, ok := allDeps["koa"]; ok {
		frameworks = append(frameworks, Framework{
			Name:       "koa",
			Version:    version,
			Language:   "javascript",
			Confidence: 1.0,
			Files:      []string{packageJSONPath},
		})
	}

	// NestJS
	if version, ok := allDeps["@nestjs/core"]; ok {
		frameworks = append(frameworks, Framework{
			Name:       "nestjs",
			Version:    version,
			Language:   "javascript",
			Confidence: 1.0,
			Files:      []string{packageJSONPath},
		})
	}

	return frameworks
}

func (d *Detector) detectPython() []Framework {
	var frameworks []Framework

	// Check requirements.txt
	reqPath := filepath.Join(d.root, "requirements.txt")
	if data, err := os.ReadFile(reqPath); err == nil {
		content := string(data)

		if strings.Contains(content, "Flask") {
			frameworks = append(frameworks, Framework{
				Name:       "flask",
				Language:   "python",
				Confidence: 1.0,
				Files:      []string{reqPath},
			})
		}
		if strings.Contains(content, "Django") {
			frameworks = append(frameworks, Framework{
				Name:       "django",
				Language:   "python",
				Confidence: 1.0,
				Files:      []string{reqPath},
			})
		}
		if strings.Contains(content, "FastAPI") {
			frameworks = append(frameworks, Framework{
				Name:       "fastapi",
				Language:   "python",
				Confidence: 1.0,
				Files:      []string{reqPath},
			})
		}
	}

	// Check pyproject.toml
	pyprojectPath := filepath.Join(d.root, "pyproject.toml")
	if data, err := os.ReadFile(pyprojectPath); err == nil {
		content := string(data)

		if strings.Contains(content, "flask") {
			frameworks = append(frameworks, Framework{
				Name:       "flask",
				Language:   "python",
				Confidence: 0.9,
				Files:      []string{pyprojectPath},
			})
		}
		if strings.Contains(content, "django") {
			frameworks = append(frameworks, Framework{
				Name:       "django",
				Language:   "python",
				Confidence: 0.9,
				Files:      []string{pyprojectPath},
			})
		}
		if strings.Contains(content, "fastapi") {
			frameworks = append(frameworks, Framework{
				Name:       "fastapi",
				Language:   "python",
				Confidence: 0.9,
				Files:      []string{pyprojectPath},
			})
		}
	}

	return frameworks
}

func (d *Detector) detectGo() []Framework {
	var frameworks []Framework

	goModPath := filepath.Join(d.root, "go.mod")
	data, err := os.ReadFile(goModPath)
	if err != nil {
		return nil
	}

	content := string(data)

	if strings.Contains(content, "github.com/gin-gonic/gin") {
		frameworks = append(frameworks, Framework{
			Name:       "gin",
			Language:   "go",
			Confidence: 1.0,
			Files:      []string{goModPath},
		})
	}
	if strings.Contains(content, "github.com/labstack/echo") {
		frameworks = append(frameworks, Framework{
			Name:       "echo",
			Language:   "go",
			Confidence: 1.0,
			Files:      []string{goModPath},
		})
	}
	if strings.Contains(content, "github.com/gofiber/fiber") {
		frameworks = append(frameworks, Framework{
			Name:       "fiber",
			Language:   "go",
			Confidence: 1.0,
			Files:      []string{goModPath},
		})
	}
	if strings.Contains(content, "net/http") {
		frameworks = append(frameworks, Framework{
			Name:       "nethttp",
			Language:   "go",
			Confidence: 0.7,
			Files:      []string{goModPath},
		})
	}

	return frameworks
}

func (d *Detector) detectPHP() []Framework {
	var frameworks []Framework

	composerPath := filepath.Join(d.root, "composer.json")
	data, err := os.ReadFile(composerPath)
	if err != nil {
		return nil
	}

	var composer struct {
		Require map[string]string `json:"require"`
	}
	if err := json.Unmarshal(data, &composer); err != nil {
		return nil
	}

	if _, ok := composer.Require["laravel/framework"]; ok {
		frameworks = append(frameworks, Framework{
			Name:       "laravel",
			Language:   "php",
			Confidence: 1.0,
			Files:      []string{composerPath},
		})
	}
	if _, ok := composer.Require["symfony/framework-bundle"]; ok {
		frameworks = append(frameworks, Framework{
			Name:       "symfony",
			Language:   "php",
			Confidence: 1.0,
			Files:      []string{composerPath},
		})
	}

	return frameworks
}

func (d *Detector) detectRust() []Framework {
	var frameworks []Framework

	cargoPath := filepath.Join(d.root, "Cargo.toml")
	data, err := os.ReadFile(cargoPath)
	if err != nil {
		return nil
	}

	content := string(data)

	if strings.Contains(content, "actix-web") {
		frameworks = append(frameworks, Framework{
			Name:       "actix",
			Language:   "rust",
			Confidence: 1.0,
			Files:      []string{cargoPath},
		})
	}
	if strings.Contains(content, "axum") {
		frameworks = append(frameworks, Framework{
			Name:       "axum",
			Language:   "rust",
			Confidence: 1.0,
			Files:      []string{cargoPath},
		})
	}
	if strings.Contains(content, "rocket") {
		frameworks = append(frameworks, Framework{
			Name:       "rocket",
			Language:   "rust",
			Confidence: 1.0,
			Files:      []string{cargoPath},
		})
	}

	return frameworks
}

func mergeMaps(a, b map[string]string) map[string]string {
	result := make(map[string]string)
	for k, v := range a {
		result[k] = v
	}
	for k, v := range b {
		result[k] = v
	}
	return result
}

// FormatFrameworks returns a human-readable string of detected frameworks
func FormatFrameworks(frameworks []Framework) string {
	if len(frameworks) == 0 {
		return "none detected"
	}

	var parts []string
	for _, fw := range frameworks {
		version := fw.Version
		if version == "" {
			version = "unknown"
		}
		parts = append(parts, fmt.Sprintf("%s@%s", fw.Name, version))
	}
	return strings.Join(parts, ", ")
}

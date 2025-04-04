package config

import (
	"encoding/json"
	"errors"
	"os"
)

type Standard struct {
	RSA       int `json:"RSA"`
	ECC       int `json:"ECC"`
	Symmetric int `json:"Symmetric"`
}

type Standards struct {
	Standards map[string]Standard `json:"standards"`
}

type Config struct {
	SelectedStandard string
	standards        Standards
}

func NewConfig(standardsFile string, selectedStandard string) (*Config, error) {
	if standardsFile == "" {
		return nil, errors.New("standards file path cannot be empty")
	}

	data, err := os.ReadFile(standardsFile)
	if err != nil {
		return nil, errors.New("failed to read standards file: " + err.Error())
	}

	var standards Standards
	if err := json.Unmarshal(data, &standards); err != nil {
		return nil, errors.New("failed to parse standards JSON: " + err.Error())
	}

	if selectedStandard == "" {
		selectedStandard = "NIST"
	}
	if _, exists := standards.Standards[selectedStandard]; !exists {
		return nil, errors.New("invalid standard: " + selectedStandard)
	}

	return &Config{
		SelectedStandard: selectedStandard,
		standards:        standards,
	}, nil
}

func (c *Config) GetThreshold(algorithm string) int {
	standard := c.standards.Standards[c.SelectedStandard]
	switch algorithm {
	case "RSA":
		return standard.RSA
	case "ECC":
		return standard.ECC
	case "Symmetric":
		return standard.Symmetric
	default:
		return 0
	}
}

func (c *Config) AvailableStandards() []string {
	standards := make([]string, 0, len(c.standards.Standards))
	for name := range c.standards.Standards {
		standards = append(standards, name)
	}
	return standards
}

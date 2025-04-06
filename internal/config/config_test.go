package config

import (
	"encoding/json"
	"os"
	"testing"
)

func TestNewConfig(t *testing.T) {
	standards := Standards{
		Standards: map[string]Standard{
			"NIST": {
				RSA:        2048,
				ECC:        256,
				Symmetric:  128,
				CutOffYear: 2030,
			},
			"BSI": {
				RSA:        3000,
				ECC:        250,
				Symmetric:  128,
				CutOffYear: 2022,
			},
		},
	}

	tempFile, err := os.CreateTemp("", "standards-*.json")
	if err != nil {
		t.Fatal("Failed to create temp file:", err)
	}
	defer os.Remove(tempFile.Name())

	data, err := json.Marshal(standards)
	if err != nil {
		t.Fatal("Failed to marshal standards:", err)
	}

	if _, err := tempFile.Write(data); err != nil {
		t.Fatal("Failed to write to temp file:", err)
	}
	tempFile.Close()

	tests := []struct {
		name             string
		standardsFile    string
		selectedStandard string
		wantErr          bool
		errorMsg         string
	}{
		{
			name:             "Valid config with default standard",
			standardsFile:    tempFile.Name(),
			selectedStandard: "",
			wantErr:          false,
		},
		{
			name:             "Valid config with specified standard",
			standardsFile:    tempFile.Name(),
			selectedStandard: "BSI",
			wantErr:          false,
		},
		{
			name:             "Empty standards file path",
			standardsFile:    "",
			selectedStandard: "NIST",
			wantErr:          true,
			errorMsg:         "standards file path cannot be empty",
		},
		{
			name:             "Non-existent standards file",
			standardsFile:    "non-existent-file.json",
			selectedStandard: "NIST",
			wantErr:          true,
			errorMsg:         "failed to read standards file",
		},
		{
			name:             "Invalid standard name",
			standardsFile:    tempFile.Name(),
			selectedStandard: "INVALID",
			wantErr:          true,
			errorMsg:         "invalid standard: INVALID",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := NewConfig(tt.standardsFile, tt.selectedStandard)
			if tt.wantErr {
				if err == nil {
					t.Errorf("Expected error but got nil")
				} else if tt.errorMsg != "" && !contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error containing %q, got %q", tt.errorMsg, err.Error())
				}
				return
			}
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			expectedStandard := tt.selectedStandard
			if expectedStandard == "" {
				expectedStandard = "NIST"
			}
			if cfg.SelectedStandard != expectedStandard {
				t.Errorf("Expected selected standard %q, got %q", expectedStandard, cfg.SelectedStandard)
			}
		})
	}
}

func TestGetThreshold(t *testing.T) {
	cfg := &Config{
		SelectedStandard: "TestStandard",
		standards: Standards{
			Standards: map[string]Standard{
				"TestStandard": {
					RSA:        2048,
					ECC:        256,
					Symmetric:  128,
					CutOffYear: 2030,
				},
				"OldStandard": {
					RSA:        2048,
					ECC:        256,
					Symmetric:  128,
					CutOffYear: 2020,
				},
			},
		},
	}

	tests := []struct {
		name          string
		standard      string
		algorithm     string
		wantThreshold int
	}{
		{
			name:          "RSA threshold with valid cutoff year",
			standard:      "TestStandard",
			algorithm:     "RSA",
			wantThreshold: 2048,
		},
		{
			name:          "RSA threshold with expired cutoff year",
			standard:      "OldStandard",
			algorithm:     "RSA",
			wantThreshold: 3072,
		},
		{
			name:          "ECC threshold",
			standard:      "TestStandard",
			algorithm:     "ECC",
			wantThreshold: 256,
		},
		{
			name:          "Symmetric threshold",
			standard:      "TestStandard",
			algorithm:     "Symmetric",
			wantThreshold: 128,
		},
		{
			name:          "Unknown algorithm",
			standard:      "TestStandard",
			algorithm:     "Unknown",
			wantThreshold: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg.SelectedStandard = tt.standard
			threshold := cfg.GetThreshold(tt.algorithm)
			if threshold != tt.wantThreshold {
				t.Errorf("GetThreshold(%q) = %d, want %d", tt.algorithm, threshold, tt.wantThreshold)
			}
		})
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && s[:len(substr)] == substr
}

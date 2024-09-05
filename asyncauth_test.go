package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDownloadUrl(t *testing.T) {
	url := "https://www.example.com/token/"

	testCases := []struct {
		platform    string
		version     string
		binary      string
		expectedURL string
	}{
		{
			platform:    "linux_amd64",
			version:     "v0.1.0",
			binary:      "konvoy-async-auth",
			expectedURL: "https://www.example.com/token/static/downloads/konvoy-async-auth_v0.1.0_linux_amd64/konvoy-async-auth",
		},
		{
			platform:    "darwin_arm64",
			version:     "v0.2.0",
			binary:      "konvoy-async-auth",
			expectedURL: "https://www.example.com/token/static/downloads/konvoy-async-auth_v0.2.0_darwin_arm64/konvoy-async-auth",
		},
		{
			platform:    "windows_amd64",
			version:     "v0.2.1",
			binary:      "konvoy-async-auth.exe",
			expectedURL: "https://www.example.com/token/static/downloads/konvoy-async-auth_v0.2.1_windows_amd64/konvoy-async-auth.exe",
		},
	}

	for _, tc := range testCases {
		downloadURL := getDownloadURL(url, tc.platform, tc.version, tc.binary)
		assert.Equal(t, downloadURL, tc.expectedURL)
	}
}

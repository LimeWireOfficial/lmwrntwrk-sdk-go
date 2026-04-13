package version

import (
	"fmt"
	"testing"
)

func TestVersionFormat(t *testing.T) {
	if SDKVersion == "" {
		t.Error("SDKVersion should not be empty")
	}
	fmt.Printf("Current SDK version: %s\n", SDKVersion)
}

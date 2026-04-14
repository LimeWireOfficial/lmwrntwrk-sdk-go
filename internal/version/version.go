package version

import "fmt"

// SDKVersion is the current version of the LimeWireNetwork SDK for Go.
var SDKVersion = "0.1.4"

// UserAgent is the pre-calculated User-Agent string for the SDK.
func UserAgent() string {
	return fmt.Sprintf("LmwrNtwrkGoSdk/%s", SDKVersion)
}

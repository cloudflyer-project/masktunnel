package masktunnel

import "runtime"

var (
	Version  = "v1.0.21"
	Platform = runtime.GOOS + "/" + runtime.GOARCH
)

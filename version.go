package masktunnel

import "runtime"

var (
	Version  = "v1.1.1"
	Platform = runtime.GOOS + "/" + runtime.GOARCH
)

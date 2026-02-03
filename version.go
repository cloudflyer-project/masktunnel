package masktunnel

import "runtime"

var (
	Version  = "v1.1.3"
	Platform = runtime.GOOS + "/" + runtime.GOARCH
)

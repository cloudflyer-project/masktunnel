package masktunnel

import "runtime"

var (
	Version  = "v1.1.5"
	Platform = runtime.GOOS + "/" + runtime.GOARCH
)

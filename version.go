package masktunnel

import "runtime"

var (
	Version  = "v1.1.2"
	Platform = runtime.GOOS + "/" + runtime.GOARCH
)

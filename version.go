package masktunnel

import "runtime"

var (
	Version  = "v1.1.6"
	Platform = runtime.GOOS + "/" + runtime.GOARCH
)

package masktunnel

import "runtime"

var (
	Version  = "v1.1.4"
	Platform = runtime.GOOS + "/" + runtime.GOARCH
)

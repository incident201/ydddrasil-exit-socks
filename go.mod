module ygg-exit-socks

go 1.24

require (
	github.com/yggdrasil-network/yggdrasil-go v0.5.13
	gvisor.dev/gvisor v0.0.0-20250812171554-968e93457fe6
)

// Keep your fork cloned next to this repository:
//   ../yggdrasil-go
// The module path inside the fork is still github.com/yggdrasil-network/yggdrasil-go.
replace github.com/yggdrasil-network/yggdrasil-go => ../yggdrasil-go

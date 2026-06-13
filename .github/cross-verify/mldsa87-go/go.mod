// Routinely-bumped pin: this module resolves the go-qrllib used by the
// ML-DSA-87 *verify* leg (JS-signed → Go-verified). Keep it on the same
// release as GO_QRLLIB_MLDSA87_PIN in cross-verify.yml (which governs the
// sign leg's clone) — bump both together when go-qrllib releases. Listed in
// CONTRIBUTING.md "Updating pinned verification upstreams".
module github.com/theQRL/qrypto.js/cross-verify/mldsa87-go

go 1.25.0

require github.com/theQRL/go-qrllib v0.9.0

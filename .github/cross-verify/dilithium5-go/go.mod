// FROZEN — do not bump. The last go-qrllib release containing
// crypto/dilithium is v0.8.0 (b2ee4790); upstream removed the package in
// v0.9.0 (1ae1760). This pseudo-version (2026-01-08, pre-removal) is a
// permanently historical reference for the frozen Dilithium5 scheme.
// It is listed in CONTRIBUTING.md "Updating pinned verification upstreams"
// alongside the workflow env pins — a go.mod requirement is a pin like any
// clone SHA: `go run` from this directory resolves go-qrllib through it.
//
// The FREEZE is on go-qrllib (the consensus-relevant reference), NOT its
// transitive deps: golang.org/x/crypto (used only for x/crypto/sha3 here)
// may be security-bumped — exactly the noble-style patch playbook. It was
// raised to v0.53.0 to clear x/crypto/ssh advisories (ssh is unused by the
// verifier); SHAKE256 output is unchanged, the d5 interop leg still passes.
module github.com/theQRL/qrypto.js/cross-verify/dilithium5-go

go 1.25.0

require github.com/theQRL/go-qrllib v0.1.3-0.20260108140359-873544fa56e8

require (
	golang.org/x/crypto v0.53.0 // indirect
	golang.org/x/sys v0.46.0 // indirect
)

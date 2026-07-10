// Package docs embeds the generated OpenAPI 3.1 document so the binary can
// serve it without reading from disk.
//
// # Why the spec is embedded rather than read at runtime
//
// A binary that reads ./docs/swagger.json at startup only works when the
// process's working directory happens to be the repository root. Embedding
// makes the document part of the binary: `scp bin/api server:` is a complete
// deployment.
//
// # Why this file exists at all, rather than swag's generated docs.go
//
// `swag init` normally emits a docs.go that registers the spec in
// github.com/swaggo/swag/v2's global registry. But github.com/swaggo/
// http-swagger/v2 — the package that serves Swagger UI — reads swag *v1*'s
// registry. Two registries, one of them always empty: /docs/doc.json returned
// 500 with that arrangement.
//
// Generating only swagger.json (`--outputTypes json,yaml`) and embedding it
// here sidesteps the incompatibility, removes a release-candidate dependency,
// and gives us OpenAPI 3.1 instead of the 2.0 that swag v1 would produce.
//
// Regenerate with: make docs
package docs

import _ "embed"

// SwaggerJSON is the OpenAPI 3.1 document, embedded at compile time.
//
// It is committed to version control so `go build` succeeds without the swag
// CLI installed. Regenerate it whenever you change an @-annotation, and commit
// the result — a stale spec is worse than no spec, because people trust it.
//
//go:embed swagger.json
var SwaggerJSON []byte

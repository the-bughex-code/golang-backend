// Package docs embeds the generated API specification so the binary can serve
// it without reading from disk.
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
// here sidesteps the incompatibility and removes a release-candidate dependency.
//
// # Why Swagger 2.0 and not OpenAPI 3.1
//
// swag can emit either, with nothing in between. The Swagger UI bundled by
// http-swagger cannot render 3.1 — it reports "Unable to render this definition"
// and lists `swagger: 2.0` and `openapi: 3.0.n` as the versions it accepts.
// Keeping 3.1 would mean vendoring ~1.4 MB of Swagger UI 5.x into this
// repository and maintaining it by hand, to gain a version number.
//
// Swagger 2.0 is also the format openapi-generator handles best, which is what
// you would use to generate a typed Dart client from this file.
//
// Regenerate with: make docs
package docs

import _ "embed"

// SwaggerJSON is the Swagger 2.0 document, embedded at compile time.
//
// It is committed to version control so `go build` succeeds without the swag
// CLI installed. Regenerate it whenever you change an @-annotation, and commit
// the result — a stale spec is worse than no spec, because people trust it.
// CI enforces this: the `docs` job regenerates and fails on any difference.
//
//go:embed swagger.json
var SwaggerJSON []byte

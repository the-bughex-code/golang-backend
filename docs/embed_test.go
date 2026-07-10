package docs

import (
	"encoding/json"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// renderableVersion is exactly the rule Swagger UI applies before it will draw
// anything: the document must declare `swagger: "2.0"`, or an `openapi` version
// matching 3.0.n. Anything else produces "Unable to render this definition".
var openapi30 = regexp.MustCompile(`^3\.0\.\d+$`)

// This test exists because of a bug that was invisible to every other check.
//
// The spec was generated as OpenAPI 3.1. `curl /docs/doc.json` returned 200,
// `swag` was happy, the JSON was valid, and CI was green. The page still
// rendered nothing but an error, because the Swagger UI bundled by
// http-swagger only understands 2.0 and 3.0.n.
//
// A 200 is not the same as a page that works.
func TestEmbeddedSpec_VersionIsRenderableBySwaggerUI(t *testing.T) {
	t.Parallel()

	var doc struct {
		Swagger string `json:"swagger"`
		OpenAPI string `json:"openapi"`
	}
	require.NoError(t, json.Unmarshal(SwaggerJSON, &doc), "the embedded spec must be valid JSON")

	renderable := doc.Swagger == "2.0" || openapi30.MatchString(doc.OpenAPI)

	assert.True(t, renderable,
		"Swagger UI renders only `swagger: \"2.0\"` or `openapi: 3.0.n`, got swagger=%q openapi=%q.\n"+
			"Did someone add --v3.1 back to the `make docs` target?",
		doc.Swagger, doc.OpenAPI)
}

// A spec with no paths is a spec nobody generated. Guards against `make docs`
// silently emitting an empty document because an annotation stopped parsing.
func TestEmbeddedSpec_HasContent(t *testing.T) {
	t.Parallel()

	var doc struct {
		Info struct {
			Title string `json:"title"`
		} `json:"info"`
		Paths               map[string]any `json:"paths"`
		SecurityDefinitions map[string]any `json:"securityDefinitions"`
	}
	require.NoError(t, json.Unmarshal(SwaggerJSON, &doc))

	assert.Equal(t, "Backend API", doc.Info.Title)
	assert.NotEmpty(t, doc.Paths, "the spec documents no endpoints")

	// The Authorize button in Swagger UI exists only if this is present. It
	// vanished silently once, when an unsupported @securityDefinitions form was
	// used, and every endpoint then referenced a scheme that did not exist.
	assert.Contains(t, doc.SecurityDefinitions, "BearerAuth",
		"without this, Swagger UI shows no Authorize button")
}

// Every authenticated route must be documented as such, or the reference lies
// about what needs a token.
func TestEmbeddedSpec_ProtectedRoutesDeclareSecurity(t *testing.T) {
	t.Parallel()

	var doc struct {
		Paths map[string]map[string]struct {
			Security []map[string][]string `json:"security"`
		} `json:"paths"`
	}
	require.NoError(t, json.Unmarshal(SwaggerJSON, &doc))

	mustBeProtected := []string{
		"/api/v1/profile",
		"/api/v1/users",
		"/api/v1/users/{id}",
		"/api/v1/roles",
	}
	for _, path := range mustBeProtected {
		ops, ok := doc.Paths[path]
		require.True(t, ok, "path %s is missing from the spec", path)
		for method, op := range ops {
			assert.NotEmpty(t, op.Security, "%s %s must declare BearerAuth", method, path)
		}
	}

	// And the public ones must not, or clients will send tokens they do not have.
	for _, path := range []string{"/api/v1/auth/login", "/api/v1/auth/register", "/health/live"} {
		ops, ok := doc.Paths[path]
		require.True(t, ok, "path %s is missing from the spec", path)
		for method, op := range ops {
			assert.Empty(t, op.Security, "%s %s must be public", method, path)
		}
	}
}

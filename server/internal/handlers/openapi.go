package handlers

import (
	_ "embed"
	"encoding/json"
	"net/http"
	"sync"

	"gopkg.in/yaml.v3"
)

// openapiSpec is the canonical OpenAPI 3.1 document. It is also the source of
// truth for the generated Go client SDK under pkg/client (see gen.go there) and
// the CI drift check (scripts/openapi-check.sh).
//
//go:embed openapi.yaml
var openapiSpec []byte

// openapiJSON holds the spec transcoded to JSON, computed once on first request.
var (
	openapiJSONOnce sync.Once
	openapiJSONData []byte
	openapiJSONErr  error
)

// specJSON converts the embedded YAML spec to JSON, caching the result. Keeping
// a single YAML source and deriving JSON on demand avoids maintaining two copies
// that can drift.
func specJSON() ([]byte, error) {
	openapiJSONOnce.Do(func() {
		var doc any
		if err := yaml.Unmarshal(openapiSpec, &doc); err != nil {
			openapiJSONErr = err
			return
		}
		openapiJSONData, openapiJSONErr = json.Marshal(doc)
	})
	return openapiJSONData, openapiJSONErr
}

// OpenAPIJSON serves the specification as JSON at /openapi.json.
func (a *API) OpenAPIJSON(w http.ResponseWriter, r *http.Request) {
	data, err := specJSON()
	if err != nil {
		http.Error(w, "openapi spec is invalid: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(data)
}

// OpenAPISpec serves the specification as YAML.
func (a *API) OpenAPISpec(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/yaml")
	_, _ = w.Write(openapiSpec)
}

// APIDocs serves a self-contained Redoc documentation UI pointed at
// /openapi.json. Redoc is a single static script, so this stays lightweight.
func (a *API) APIDocs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(redocHTML))
}

// SwaggerUI serves a Swagger UI documentation page (kept for backwards
// compatibility at /api/docs). It also renders /openapi.json.
func (a *API) SwaggerUI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(swaggerHTML))
}

const redocHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Secsy PKI — API Reference</title>
  <style>body { margin: 0; padding: 0; }</style>
</head>
<body>
  <redoc spec-url="/openapi.json"></redoc>
  <script src="https://cdn.redoc.ly/redoc/latest/bundles/redoc.standalone.js"></script>
</body>
</html>`

const swaggerHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Secsy PKI — API Docs</title>
  <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css">
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
  <script>
    SwaggerUIBundle({
      url: "/openapi.json",
      dom_id: '#swagger-ui',
      deepLinking: true,
      presets: [SwaggerUIBundle.presets.apis],
    });
  </script>
</body>
</html>`

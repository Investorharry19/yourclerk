package http

import (
	_ "embed"
	nethttp "net/http"
)

// openapi.json is the single source of truth for the API reference.
// TestOpenAPIMatchesRouter fails if a route and the spec drift apart.
//
//go:embed openapi.json
var openAPISpec []byte

// swaggerUIVersion is pinned so the page cannot change under you.
const swaggerUIVersion = "5.17.14"

const docsPage = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>yourclerk API</title>
  <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@` + swaggerUIVersion + `/swagger-ui.css">
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://unpkg.com/swagger-ui-dist@` + swaggerUIVersion + `/swagger-ui-bundle.js"></script>
  <script>
    window.ui = SwaggerUIBundle({
      url: "/openapi.json",
      dom_id: "#swagger-ui",
      deepLinking: true,
      persistAuthorization: true,
      tryItOutEnabled: true
    });
  </script>
</body>
</html>`

func (s *Server) handleDocs(w nethttp.ResponseWriter, r *nethttp.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(docsPage))
}

func (s *Server) handleOpenAPI(w nethttp.ResponseWriter, r *nethttp.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(openAPISpec)
}

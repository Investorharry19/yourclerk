package http

import (
	"encoding/json"
	"io"
	"log/slog"
	nethttp "net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
)

func docsServer(enable bool) nethttp.Handler {
	users := newFakeUsers()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return NewServer(log, fakeDB{}, users, newFakeSessions(users), Options{EnableDocs: enable}).Handler()
}

func TestDocsServed(t *testing.T) {
	h := docsServer(true)

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/docs", nil))
	if rr.Code != 200 || !strings.HasPrefix(rr.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("/docs = %d %s", rr.Code, rr.Header().Get("Content-Type"))
	}
	if body := rr.Body.String(); !strings.Contains(body, "swagger-ui-bundle.js") || !strings.Contains(body, "/openapi.json") {
		t.Fatalf("/docs does not load Swagger UI: %s", body)
	}

	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("GET", "/openapi.json", nil))
	if rr.Code != 200 {
		t.Fatalf("/openapi.json = %d", rr.Code)
	}
	var spec map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &spec); err != nil {
		t.Fatalf("served spec is not valid JSON: %v", err)
	}
	if spec["openapi"] != "3.0.3" {
		t.Fatalf("openapi version = %v", spec["openapi"])
	}
}

func TestDocsDisabled(t *testing.T) {
	h := docsServer(false)
	for _, path := range []string{"/docs", "/openapi.json"} {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest("GET", path, nil))
		if rr.Code != 404 {
			t.Errorf("%s with docs disabled = %d, want 404", path, rr.Code)
		}
	}
}

// TestOpenAPIMatchesRouter fails when a route is added without documenting it,
// or documented without existing. Keep openapi.json in step with server.go.
func TestOpenAPIMatchesRouter(t *testing.T) {
	var spec struct {
		Paths map[string]map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(openAPISpec, &spec); err != nil {
		t.Fatalf("openapi.json: %v", err)
	}
	documented := map[string]bool{}
	for path, ops := range spec.Paths {
		for method := range ops {
			documented[strings.ToUpper(method)+" "+path] = true
		}
	}

	// The docs endpoints describe themselves and are not listed in the spec.
	skip := map[string]bool{"GET /docs": true, "GET /openapi.json": true}

	implemented := map[string]bool{}
	router := docsServer(true).(chi.Routes)
	err := chi.Walk(router, func(method, route string, _ nethttp.Handler, _ ...func(nethttp.Handler) nethttp.Handler) error {
		key := method + " " + route
		if !skip[key] {
			implemented[key] = true
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	var missingDocs, missingRoutes []string
	for k := range implemented {
		if !documented[k] {
			missingDocs = append(missingDocs, k)
		}
	}
	for k := range documented {
		if !implemented[k] {
			missingRoutes = append(missingRoutes, k)
		}
	}
	sort.Strings(missingDocs)
	sort.Strings(missingRoutes)
	if len(missingDocs) > 0 {
		t.Errorf("routes missing from openapi.json: %v", missingDocs)
	}
	if len(missingRoutes) > 0 {
		t.Errorf("documented in openapi.json but not routed: %v", missingRoutes)
	}
}

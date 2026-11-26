package update

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

type fixtureTransport func(*http.Request) (*http.Response, error)

func (f fixtureTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func response(body string, status int) *http.Response {
	return &http.Response{
		StatusCode: status, Body: io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)), Header: http.Header{},
	}
}

func testSource(t *testing.T) (*source, *http.ServeMux, *string) {
	t.Helper()
	const payload = "archive bytes fixture"
	sum := sha256.Sum256([]byte(payload))
	s := &source{
		version: "v1.1.0", repo: "fixture/imon", dataPath: t.TempDir(),
		assetName: "imon-web_linux_amd64.tar.gz",
	}
	download := payload
	s.client = &http.Client{Transport: fixtureTransport(func(r *http.Request) (*http.Response, error) {
		switch r.URL.String() {
		case "https://api.github.com/repos/fixture/imon/releases/latest":
			data, err := json.Marshal(release{
				Tag: "v1.2.0", Assets: []asset{
					{Name: "other-platform.zip", Digest: "sha256:" + hex.EncodeToString(sum[:]), Size: int64(len(payload)), State: "uploaded"},
					{Name: s.assetName, Digest: "sha256:" + hex.EncodeToString(sum[:]), Size: int64(len(payload)), State: "uploaded"},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			return response(string(data), http.StatusOK), nil
		case "https://github.com/fixture/imon/releases/download/v1.2.0/imon-web_linux_amd64.tar.gz":
			return response(download, http.StatusOK), nil
		default:
			t.Fatalf("unexpected outbound request: %s", r.URL.String())
			return nil, nil
		}
	})}
	mux := http.NewServeMux()
	s.register(mux)
	return s, mux, &download
}

func makeRequest(mux *http.ServeMux, method, path, body string) *httptest.ResponseRecorder {
	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, httptest.NewRequest(method, path, strings.NewReader(body)))
	return recorder
}

func readInfo(t *testing.T, recorder *httptest.ResponseRecorder, status int) info {
	t.Helper()
	var decoded info
	if recorder.Code != status {
		t.Fatalf("HTTP %d: %s", recorder.Code, recorder.Body.String())
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	return decoded
}

func TestRegisterLocalVersion(t *testing.T) {
	mux := http.NewServeMux()
	if err := Register(mux, t.TempDir(), "dev", ""); err != nil {
		t.Fatal(err)
	}
	withoutRepo := readInfo(t, makeRequest(mux, "GET", "/api/v1/version", ""), http.StatusOK)
	if withoutRepo.Current != "dev" || withoutRepo.State != "unconfigured" {
		t.Fatalf("unexpected local version: %+v", withoutRepo)
	}
	if err := Register(http.NewServeMux(), t.TempDir(), "dev", "fixture/.."); err == nil {
		t.Fatal("accepted invalid repository")
	}
}

func TestCheckAndDownload(t *testing.T) {
	s, mux, payload := testSource(t)
	const endpoint = "/api/v1/version/update"
	checked := readInfo(t, makeRequest(mux, "GET", endpoint, ""), http.StatusOK)
	if checked.Current != s.version || checked.Tag != "v1.2.0" || checked.AssetName != s.assetName || checked.State != "available" {
		t.Fatalf("unexpected update: %+v", checked)
	}
	wrong := makeRequest(mux, "POST", endpoint, `{"tag":"v1.2.0","sha256":"changed"}`)
	if wrong.Code != http.StatusConflict || !strings.Contains(wrong.Body.String(), "release_changed") {
		t.Fatalf("did not reject changed release: %d %s", wrong.Code, wrong.Body.String())
	}
	request := `{"tag":"v1.2.0","sha256":"` + checked.SHA256 + `"}`
	original := *payload
	*payload = strings.Repeat("x", len(original))
	failed := makeRequest(mux, "POST", endpoint, request)
	if failed.Code != http.StatusBadGateway || !strings.Contains(failed.Body.String(), "checksum_mismatch") {
		t.Fatalf("did not reject bad binary: %d %s", failed.Code, failed.Body.String())
	}
	dir := filepath.Join(s.dataPath, "updates", checked.Tag)
	contents, err := os.ReadDir(dir)
	if err != nil || len(contents) != 0 {
		t.Fatalf("failed download left files: %v %v", contents, err)
	}
	*payload = original
	staged := readInfo(t, makeRequest(mux, "POST", endpoint, request), http.StatusOK)
	if staged.State != "downloaded" || staged.Path != filepath.Join(dir, s.assetName) {
		t.Fatalf("unexpected staged result: %+v", staged)
	}
	if bytes, err := os.ReadFile(staged.Path); err != nil || string(bytes) != original {
		t.Fatalf("staged archive not preserved: %v", err)
	}
	*payload = "unavailable"
	if repeated := readInfo(t, makeRequest(mux, "POST", endpoint, request), http.StatusOK); repeated.Path != staged.Path {
		t.Fatal("verified archive was not reused")
	}
	s.version = "v1.2.0"
	if upToDate := readInfo(t, makeRequest(mux, "GET", endpoint, ""), http.StatusOK); upToDate.State != "up_to_date" {
		t.Fatalf("unexpected state: %+v", upToDate)
	}
}

func TestStartupCheckSharesOneLookupAcrossTabs(t *testing.T) {
	s, mux, _ := testSource(t)
	transport := s.client.Transport
	var calls atomic.Int32
	entered := make(chan struct{})
	finish := make(chan struct{})
	s.client.Transport = fixtureTransport(func(r *http.Request) (*http.Response, error) {
		if calls.Add(1) == 1 {
			close(entered)
			<-finish
		}
		return transport.RoundTrip(r)
	})
	const endpoint = "/api/v1/version/update"
	var tabs sync.WaitGroup
	results := make(chan *httptest.ResponseRecorder, 8)
	for range cap(results) {
		tabs.Go(func() {
			results <- makeRequest(mux, "GET", endpoint+"?startup=1", "")
		})
	}
	<-entered
	close(finish)
	tabs.Wait()
	close(results)
	for result := range results {
		if got := readInfo(t, result, http.StatusOK); got.Tag != "v1.2.0" || got.State != "available" {
			t.Fatalf("unexpected startup check result: %+v", got)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("startup GitHub calls = %d; want 1", got)
	}
	readInfo(t, makeRequest(mux, "GET", endpoint, ""), http.StatusOK)
	if got := calls.Load(); got != 2 {
		t.Fatalf("manual check did not perform a fresh lookup: calls=%d", got)
	}
}

func TestRedirectHost(t *testing.T) {
	for _, test := range []struct {
		url string
		ok  bool
	}{
		{"https://release-assets.githubusercontent.com/fixture", true},
		{"https://github.com/fixture", true},
		{"http://github.com/fixture", false},
		{"https://github.com:8443/fixture", false},
		{"https://github.com.example.invalid/fixture", false},
	} {
		request, err := http.NewRequest("GET", test.url, nil)
		if err != nil {
			t.Fatal(err)
		}
		if passed := checkRedirect(request, nil) == nil; passed != test.ok {
			t.Fatalf("%s accepted=%t, want=%t", test.url, passed, test.ok)
		}
	}
}

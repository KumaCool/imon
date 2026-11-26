package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const pickerRoute = "/api/v1/local/file-picker"

func TestLocalFilePickerRoute(t *testing.T) {
	p := &businessAPI{picker: make(chan struct{}, 1)}
	h, _, err := NewWeb(testHost, p.routes(), "")
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	key := filepath.Join(t.TempDir(), "fixture key")
	p.chooseFile = func(ctx context.Context) (string, error) {
		calls++
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("file picker without timeout")
		}
		return key, nil
	}
	origin := "http://" + testHost
	login := exchange(h, origin)
	status(t, login, 204)
	cookie := login.Result().Cookies()[0]
	authenticate := func(r *http.Request) {
		r.AddCookie(cookie)
		r.Header.Set("Origin", origin)
	}
	status(t, request(h, "POST", pickerRoute, "", func(r *http.Request) { r.Header.Set("Origin", origin) }), 401)
	status(t, request(h, "POST", pickerRoute, "", func(r *http.Request) { r.AddCookie(cookie) }), 403)
	status(t, request(h, "POST", pickerRoute, "", func(r *http.Request) {
		authenticate(r)
		r.Header.Set("Sec-Fetch-Site", "cross-site")
	}), 403)
	status(t, request(h, "GET", pickerRoute, "", authenticate), 405)
	status(t, request(h, "POST", pickerRoute, `{"path":"<PLACEHOLDER>"}`, authenticate), 400)
	p.picker <- struct{}{}
	w := request(h, "POST", pickerRoute, "", authenticate)
	status(t, w, 409)
	if !strings.Contains(w.Body.String(), `"code":"local_picker_busy"`) {
		t.Fatal("missing busy error code")
	}
	<-p.picker
	if calls != 0 {
		t.Fatalf("rejected requests opened %d dialogs", calls)
	}
	w = request(h, "POST", pickerRoute, "", authenticate)
	status(t, w, 200)
	var response map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil || len(response) != 1 || response["path"] != key || calls != 1 {
		t.Fatal("file picker did not return only the selected path")
	}
	for _, test := range []struct {
		name string
		err  error
		want int
		code string
	}{
		{"cancel", nil, 204, ""},
		{"timeout", context.DeadlineExceeded, 504, "local_picker_timeout"},
		{"unavailable", errors.New("<INTERNAL_ERROR_DETAIL>"), 503, "local_picker_unavailable"},
	} {
		t.Run(test.name, func(t *testing.T) {
			p.chooseFile = func(context.Context) (string, error) { return "", test.err }
			w := request(h, "POST", pickerRoute, "", authenticate)
			status(t, w, test.want)
			if test.code == "" && w.Body.Len() != 0 || test.code != "" && !strings.Contains(w.Body.String(), `"code":"`+test.code+`"`) {
				t.Fatal("incorrect response")
			}
			if strings.Contains(w.Body.String(), "INTERNAL_ERROR_DETAIL") {
				t.Fatal("internal error details exposed")
			}
		})
	}
}

func TestParseLocalFilePath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fixture key")
	if err := os.WriteFile(path, []byte("<FAKE_FIXTURE_CONTENT>"), 0600); err != nil {
		t.Fatal(err)
	}
	terminator := "\n"
	if runtime.GOOS == "windows" {
		terminator = ""
	}
	for _, test := range []struct {
		input string
		want  string
		ok    bool
	}{
		{path + terminator, path, true},
		{terminator, "", true},
		{"./relative" + terminator, "", false},
		{dir + terminator, "", false},
		{filepath.Join(dir, "missing") + terminator, "", false},
		{path + "\nextra" + terminator, "", false},
		{path + "\x00" + terminator, "", false},
		{path + "\xff" + terminator, "", false},
	} {
		got, err := parseLocalFilePath([]byte(test.input))
		if got != test.want || (err == nil) != test.ok {
			t.Errorf("parseLocalFilePath(%q) = %q, %v; want %q, success=%t", test.input, got, err, test.want, test.ok)
		}
	}
}

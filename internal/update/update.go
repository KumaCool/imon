// Package update checks GitHub Releases and prepares verified updates.
package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const maxArchiveSize = 128 << 20
const maxReleaseMetadata = 2 << 20
const downloadTimeout = 3 * time.Minute

var (
	repoPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,39}/[A-Za-z0-9_.-]{1,100}$`)
	versionPattern = regexp.MustCompile(`^v?(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})$`)
	errNoRelease   = errors.New("no release")
	errRateLimit   = errors.New("GitHub rate limit")
	errChecksum    = errors.New("archive digest or size mismatch")
	errArchive     = errors.New("invalid release archive")
)

type source struct {
	dataPath    string
	version     string
	repo        string
	assetName   string
	client      *http.Client
	busy        sync.Mutex
	install     func(*http.Request, *Replacement) error
	executable  string
	rolledBack  atomic.Bool
	startupMu   sync.Mutex
	startupDone chan struct{}
	startupInfo info
	startupErr  error
}

type release struct {
	Tag        string  `json:"tag_name"`
	Name       string  `json:"name"`
	Body       string  `json:"body"`
	Draft      bool    `json:"draft"`
	Prerelease bool    `json:"prerelease"`
	Assets     []asset `json:"assets"`
}

type asset struct {
	Name   string `json:"name"`
	Digest string `json:"digest"`
	Size   int64  `json:"size"`
	State  string `json:"state"`
}

type info struct {
	Current      string `json:"current"`
	Repository   string `json:"repository,omitempty"`
	State        string `json:"state"`
	Tag          string `json:"tag,omitempty"`
	AssetName    string `json:"asset_name,omitempty"`
	Size         int64  `json:"size,omitempty"`
	SHA256       string `json:"sha256,omitempty"`
	Path         string `json:"path,omitempty"`
	ReleaseURL   string `json:"release_url,omitempty"`
	ReleaseName  string `json:"release_name,omitempty"`
	ReleaseNotes string `json:"release_notes,omitempty"`
	CanApply     bool   `json:"can_apply"`
}

type Options struct {
	Executable string
	Install    func(*http.Request, *Replacement) error
	RolledBack bool
}

// Register adds version and update endpoints to the authenticated local API.
func Register(mux *http.ServeMux, dataPath, version, repo string, options ...Options) error {
	repo = strings.TrimSpace(repo)
	if repo != "" && !validRepo(repo) {
		return errors.New("GitHub release repository must be owner/repo")
	}
	extension := ".tar.gz"
	if runtime.GOOS == "windows" {
		extension = ".zip"
	}
	s := &source{
		dataPath: dataPath, version: version, repo: repo,
		assetName: "imon-web_" + runtime.GOOS + "_" + runtime.GOARCH + extension,
		client:    &http.Client{CheckRedirect: checkRedirect},
	}
	if len(options) != 0 {
		s.rolledBack.Store(options[0].RolledBack)
		if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
			s.executable, s.install = options[0].Executable, options[0].Install
		}
	}
	s.register(mux)
	return nil
}

func validRepo(repo string) bool {
	if !repoPattern.MatchString(repo) {
		return false
	}
	_, name, _ := strings.Cut(repo, "/")
	return name != "." && name != ".."
}

func checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 5 || req.URL.Scheme != "https" || req.URL.User != nil || req.URL.Port() != "" {
		return errors.New("invalid GitHub release redirect")
	}
	switch req.URL.Hostname() {
	case "api.github.com", "github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com":
		return nil
	default:
		return errors.New("invalid GitHub release host")
	}
}

func (s *source) register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/version", s.localVersion)
	mux.HandleFunc("GET /api/v1/version/update", s.check)
	mux.HandleFunc("POST /api/v1/version/update", s.download)
	mux.HandleFunc("POST /api/v1/version/update/apply", s.apply)
}

func (s *source) local() info {
	state := "configured"
	if s.repo == "" {
		state = "unconfigured"
	}
	canApply := s.repo != "" && s.executable != "" && s.install != nil
	return info{Current: s.version, Repository: s.repo, State: state, CanApply: canApply}
}

func (s *source) localVersion(w http.ResponseWriter, r *http.Request) {
	current := s.local()
	if s.rolledBack.Load() {
		current.State = "rolled_back"
	}
	respond(w, http.StatusOK, current)
}

func (s *source) check(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()
	var current info
	var err error
	if r.URL.Query().Get("startup") == "1" {
		current, err = s.startupLookup(ctx)
	} else {
		current, err = s.lookup(ctx)
	}
	if err != nil {
		report(w, err)
		return
	}
	respond(w, http.StatusOK, current)
}

func (s *source) startupLookup(ctx context.Context) (info, error) {
	s.startupMu.Lock()
	if s.startupDone == nil {
		s.startupDone = make(chan struct{})
		go func() {
			// The first browser can close without canceling the process-wide check.
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()
			s.startupInfo, s.startupErr = s.lookup(ctx)
			close(s.startupDone)
		}()
	}
	done := s.startupDone
	s.startupMu.Unlock()
	select {
	case <-done:
		return s.startupInfo, s.startupErr
	case <-ctx.Done():
		return info{}, ctx.Err()
	}
}

func (s *source) lookup(ctx context.Context) (info, error) {
	current := s.local()
	if s.repo == "" {
		return current, nil
	}
	url := "https://api.github.com/repos/" + s.repo + "/releases/latest"
	response, err := s.request(ctx, url, "application/vnd.github+json")
	if errors.Is(err, errNoRelease) {
		current.State = "no_release"
		return current, nil
	}
	if err != nil {
		return current, err
	}
	defer response.Body.Close()
	if response.ContentLength > maxReleaseMetadata {
		return current, errors.New("release metadata too large")
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, maxReleaseMetadata+1))
	var remote release
	if err := decoder.Decode(&remote); err != nil {
		return current, err
	}
	if _, valid := parseVersion(remote.Tag); !valid || !strings.HasPrefix(remote.Tag, "v") || remote.Draft || remote.Prerelease {
		current.State = "no_release"
		return current, nil
	}
	current.Tag = remote.Tag
	current.ReleaseURL = "https://github.com/" + s.repo + "/releases/tag/" + remote.Tag
	current.ReleaseName = truncateText(remote.Name, 160)
	current.ReleaseNotes = truncateText(remote.Body, 1600)
	if installed, valid := parseVersion(s.version); valid {
		available, _ := parseVersion(remote.Tag)
		if versionCompare(installed, available) >= 0 {
			current.State = "up_to_date"
			return current, nil
		}
	}
	current.State = "asset_missing"
	for _, candidate := range remote.Assets {
		if candidate.Name != s.assetName || candidate.State != "uploaded" {
			continue
		}
		current.State = "asset_unverified"
		digest, ok := sha256Digest(candidate.Digest)
		if !ok || candidate.Size < 1 || candidate.Size > maxArchiveSize {
			return current, nil
		}
		current.AssetName, current.SHA256, current.Size, current.State = candidate.Name, digest, candidate.Size, "available"
		return current, nil
	}
	return current, nil
}

func truncateText(text string, limit int) string {
	text = strings.TrimSpace(text)
	for index := range text {
		if limit == 0 {
			return text[:index] + "…"
		}
		limit--
	}
	return text
}

func parseVersion(version string) ([3]int, bool) {
	var result [3]int
	parts := versionPattern.FindStringSubmatch(version)
	if parts == nil {
		return result, false
	}
	for index := range result {
		result[index], _ = strconv.Atoi(parts[index+1])
	}
	return result, true
}

func versionCompare(left, right [3]int) int {
	for index := range left {
		if left[index] < right[index] {
			return -1
		}
		if left[index] > right[index] {
			return 1
		}
	}
	return 0
}

func sha256Digest(raw string) (string, bool) {
	value, ok := strings.CutPrefix(raw, "sha256:")
	if !ok || len(value) != 2*sha256.Size {
		return "", false
	}
	_, err := hex.DecodeString(value)
	return strings.ToLower(value), err == nil
}

func (s *source) request(ctx context.Context, url, accept string) (*http.Response, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("User-Agent", "Imon")
	request.Header.Set("Accept", accept)
	if request.URL.Host == "api.github.com" {
		request.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	}
	response, err := s.client.Do(request)
	if err != nil {
		return nil, err
	}
	if response.StatusCode == http.StatusOK {
		return response, nil
	}
	response.Body.Close()
	if response.StatusCode == http.StatusNotFound {
		return nil, errNoRelease
	}
	if response.StatusCode == http.StatusTooManyRequests ||
		(response.StatusCode == http.StatusForbidden && (response.Header.Get("X-RateLimit-Remaining") == "0" || response.Header.Get("Retry-After") != "")) {
		return nil, errRateLimit
	}
	return nil, fmt.Errorf("GitHub returned HTTP %d", response.StatusCode)
}

func (s *source) download(w http.ResponseWriter, r *http.Request) {
	s.transfer(w, r, false)
}

func (s *source) apply(w http.ResponseWriter, r *http.Request) {
	if !s.local().CanApply {
		fail(w, http.StatusConflict, "apply_unavailable", "此安装方式不支持自动更新。", false)
		return
	}
	s.transfer(w, r, true)
}

func (s *source) transfer(w http.ResponseWriter, r *http.Request, apply bool) {
	var selection struct {
		Tag    string `json:"tag"`
		SHA256 string `json:"sha256"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&selection); err != nil || decoder.Decode(new(any)) != io.EOF ||
		selection.Tag == "" || selection.SHA256 == "" {
		fail(w, http.StatusBadRequest, "invalid_request", "请选择已检查的发布包。", false)
		return
	}
	if !s.busy.TryLock() {
		fail(w, http.StatusConflict, "download_busy", "已有下载任务正在运行。", true)
		return
	}
	queued := false
	defer func() {
		if !queued {
			s.busy.Unlock()
		}
	}()

	// A verified archive may take longer than the normal local API write timeout.
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(downloadTimeout + 10*time.Second))
	ctx, cancel := context.WithTimeout(r.Context(), downloadTimeout)
	defer cancel()
	current, err := s.lookup(ctx)
	if err != nil {
		report(w, err)
		return
	}
	if current.State != "available" || current.Tag != selection.Tag || current.SHA256 != selection.SHA256 {
		fail(w, http.StatusConflict, "release_changed", "可下载的发布包已变化，请重新检查版本。", true)
		return
	}
	path, err := s.stage(ctx, current)
	if err != nil {
		report(w, err)
		return
	}
	if apply {
		replacement, err := prepare(ctx, s.executable, path, current)
		if err != nil {
			if errors.Is(err, errArchive) || errors.Is(err, errChecksum) {
				fail(w, http.StatusBadGateway, "invalid_update_archive", "发布包内的程序或版本校验失败。", false)
			} else {
				fail(w, http.StatusServiceUnavailable, "install_unavailable", "程序目录不可更新，请检查写入权限或使用 GitHub 发布包。", false)
			}
			return
		}
		if err := s.install(r, replacement); err != nil {
			replacement.Cleanup()
			fail(w, http.StatusServiceUnavailable, "restart_unavailable", "当前应用未能安排重启。", true)
			return
		}
		queued = true
		s.rolledBack.Store(false)
		current.State = "restarting"
		respond(w, http.StatusAccepted, current)
		return
	}
	current.State, current.Path = "downloaded", path
	respond(w, http.StatusOK, current)
}

func (s *source) stage(ctx context.Context, current info) (string, error) {
	dir := filepath.Join(s.dataPath, "updates", current.Tag)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	destination := filepath.Join(dir, current.AssetName)
	if fileMatches(destination, current) {
		return destination, nil
	}
	url := "https://github.com/" + s.repo + "/releases/download/" + current.Tag + "/" + current.AssetName
	response, err := s.request(ctx, url, "application/octet-stream")
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.ContentLength >= 0 && response.ContentLength != current.Size {
		return "", errChecksum
	}
	file, err := os.CreateTemp(dir, ".partial-*")
	if err != nil {
		return "", err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	digest := sha256.New()
	written, err := io.Copy(io.MultiWriter(file, digest), io.LimitReader(response.Body, current.Size+1))
	if err != nil {
		return "", err
	}
	if written != current.Size || hex.EncodeToString(digest.Sum(nil)) != current.SHA256 {
		return "", errChecksum
	}
	if err := file.Sync(); err != nil {
		return "", err
	}
	if err := file.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(file.Name(), destination); err != nil {
		return "", err
	}
	return destination, nil
}

func fileMatches(path string, current info) bool {
	stat, err := os.Lstat(path)
	if err != nil || !stat.Mode().IsRegular() || stat.Size() != current.Size {
		return false
	}
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	defer file.Close()
	digest := sha256.New()
	size, err := io.Copy(digest, io.LimitReader(file, current.Size+1))
	return err == nil && size == current.Size && hex.EncodeToString(digest.Sum(nil)) == current.SHA256
}

func report(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errChecksum):
		fail(w, http.StatusBadGateway, "checksum_mismatch", "发布包大小或 SHA-256 校验不匹配。", false)
	case errors.Is(err, errRateLimit):
		fail(w, http.StatusTooManyRequests, "github_rate_limited", "GitHub 请求频率受限，请稍后重试。", true)
	case errors.Is(err, errNoRelease):
		fail(w, http.StatusNotFound, "asset_missing", "GitHub 上的发布包已不可用，请重新检查版本。", true)
	case errors.Is(err, context.DeadlineExceeded):
		fail(w, http.StatusGatewayTimeout, "update_timeout", "获取发布信息或下载超时。", true)
	case errors.Is(err, os.ErrPermission):
		fail(w, http.StatusServiceUnavailable, "storage_unavailable", "本地数据目录不可写。", true)
	default:
		var diskError *os.PathError
		if errors.As(err, &diskError) {
			fail(w, http.StatusServiceUnavailable, "storage_unavailable", "保存发布包失败，请检查本地数据目录。", true)
		} else {
			fail(w, http.StatusBadGateway, "github_unavailable", "读取 GitHub 发布信息或下载失败。", true)
		}
	}
}

func fail(w http.ResponseWriter, status int, code, message string, retryable bool) {
	respond(w, status, map[string]any{"code": code, "message": message, "retryable": retryable})
}

func respond(w http.ResponseWriter, status int, result any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(result)
}

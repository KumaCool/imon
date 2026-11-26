package collector

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientconfig "k8s.io/client-go/tools/clientcmd/api"
)

const (
	maxPluginBinary = 256 << 20
	maxPluginOutput = 1 << 20
	pluginTimeout   = 10 * time.Second
)

type approvedPlugin struct {
	path   string
	digest string
	exec   *clientconfig.ExecConfig
}

func readPlugin(execCfg *clientconfig.ExecConfig, cluster *clientconfig.Cluster) (*approvedPlugin, error) {
	if !filepath.IsAbs(execCfg.Command) || execCfg.InteractiveMode == clientconfig.AlwaysExecInteractiveMode {
		return nil, fail("exec_approval_required")
	}
	file, err := readRegularDigest(execCfg.Command, maxPluginBinary)
	if err != nil {
		return nil, err
	}
	caDigest := ""
	if cluster.CertificateAuthority != "" && len(cluster.CertificateAuthorityData) == 0 {
		ca, err := readRegularDigest(cluster.CertificateAuthority, 4<<20)
		if err != nil {
			return nil, fail("invalid_kube_tls_or_credentials")
		}
		caDigest = ca.digest
	}
	approval := struct {
		File     pluginFile
		Exec     *clientconfig.ExecConfig
		Cluster  *clientconfig.Cluster
		CADigest string
	}{file, execCfg, cluster, caDigest}
	// Include the canonical path and the bytes it resolved to, in addition
	// to the entire selected plugin and Cluster records.
	encoded, err := json.Marshal(struct {
		Path        string
		BytesDigest string
		Approval    any
	}{file.path, file.digest, approval})
	if err != nil {
		return nil, fail("exec_approval_required")
	}
	sum := sha256.Sum256(encoded)
	return &approvedPlugin{path: file.path, digest: hex.EncodeToString(sum[:]), exec: execCfg}, nil
}

type pluginFile struct{ path, digest string }

func readRegularDigest(path string, maximum int64) (pluginFile, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return pluginFile{}, fail("exec_approval_required")
	}
	stat, err := os.Stat(resolved)
	if err != nil || !stat.Mode().IsRegular() || stat.Size() > maximum {
		return pluginFile{}, fail("exec_approval_required")
	}
	file, err := os.Open(resolved)
	if err != nil {
		return pluginFile{}, fail("exec_approval_required")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(stat, opened) {
		return pluginFile{}, fail("exec_approval_required")
	}
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(file, maximum+1))
	if err != nil || n > maximum {
		return pluginFile{}, fail("exec_approval_required")
	}
	return pluginFile{path: resolved, digest: hex.EncodeToString(hash.Sum(nil))}, nil
}

// KubeExecApproval returns the digest for the selected kubeconfig login plugin
// and the cluster configuration supplied to it.
func KubeExecApproval(path, contextName string) (string, error) {
	raw, err := readKubeconfig(path)
	if err != nil {
		return "", err
	}
	if contextName == "" {
		contextName = raw.CurrentContext
	}
	selected := raw.Contexts[contextName]
	if selected == nil || raw.Clusters[selected.Cluster] == nil {
		return "", fail("invalid_context")
	}
	auth := raw.AuthInfos[selected.AuthInfo]
	if auth == nil || auth.Exec == nil {
		return "", fail("exec_not_configured")
	}
	plugin, err := readPlugin(auth.Exec, raw.Clusters[selected.Cluster])
	if err != nil {
		return "", err
	}
	return plugin.digest, nil
}

func readKubeconfig(path string) (*clientconfig.Config, error) {
	if path == "" {
		return nil, fail("invalid_kubeconfig")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, fail("invalid_kubeconfig")
	}
	stat, err := os.Stat(absolute)
	if err != nil || !stat.Mode().IsRegular() || stat.Size() > 4<<20 {
		return nil, fail("credential_unreadable")
	}
	file, err := os.Open(absolute)
	if err != nil {
		return nil, fail("credential_unreadable")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(stat, opened) {
		return nil, fail("credential_unreadable")
	}
	data, err := io.ReadAll(io.LimitReader(file, (4<<20)+1))
	if err != nil || len(data) > 4<<20 {
		return nil, fail("credential_unreadable")
	}
	defer clear(data)
	loaded, err := clientcmd.Load(data)
	if err != nil {
		return nil, fail("invalid_kubeconfig")
	}
	base := filepath.Dir(absolute)
	for _, cluster := range loaded.Clusters {
		if cluster != nil {
			_ = clientcmd.ResolvePaths(clientcmd.GetClusterFileReferences(cluster), base)
		}
	}
	for _, auth := range loaded.AuthInfos {
		if auth != nil {
			_ = clientcmd.ResolvePaths([]*string{&auth.ClientKey, &auth.ClientCertificate, &auth.TokenFile}, base)
		}
	}
	return loaded, nil
}

type pluginCredential struct {
	Kind    string `json:"kind"`
	Version string `json:"apiVersion"`
	Status  *struct {
		Token       string     `json:"token,omitempty"`
		Certificate string     `json:"clientCertificateData,omitempty"`
		Key         string     `json:"clientKeyData,omitempty"`
		Expires     *time.Time `json:"expirationTimestamp,omitempty"`
	} `json:"status"`
}

type pluginBuffer struct {
	*bytes.Buffer
	oversize bool
}

func (b *pluginBuffer) Write(p []byte) (int, error) {
	if len(p) > maxPluginOutput-b.Len() {
		b.oversize = true
		return 0, fail("output_limit")
	}
	return b.Buffer.Write(p)
}

func (p *approvedPlugin) authenticate(ctx context.Context, cfg *rest.Config) error {
	var err error
	switch p.exec.APIVersion {
	case "client.authentication.k8s.io/v1", "client.authentication.k8s.io/v1beta1":
	default:
		return fail("exec_version_unsupported")
	}
	if cfg.BearerToken != "" || cfg.BearerTokenFile != "" || cfg.CertData != nil || cfg.CertFile != "" || cfg.Username != "" || cfg.Password != "" {
		return fail("exec_auth_conflict")
	}
	spec := map[string]any{"interactive": false}
	if p.exec.ProvideClusterInfo {
		cluster, err := rest.ConfigToExecCluster(cfg)
		if err != nil {
			return fail("invalid_kube_tls_or_credentials")
		}
		config, err := json.Marshal(cluster.Config)
		if err != nil {
			return fail("invalid_kubeconfig")
		}
		fields := map[string]any{
			"server":                     cluster.Server,
			"tls-server-name":            cluster.TLSServerName,
			"certificate-authority-data": cluster.CertificateAuthorityData,
			"proxy-url":                  cluster.ProxyURL,
			"disable-compression":        cluster.DisableCompression,
		}
		if string(config) != "null" {
			fields["config"] = json.RawMessage(config)
		}
		spec["cluster"] = fields
	}
	request, err := json.Marshal(map[string]any{"apiVersion": p.exec.APIVersion, "kind": "ExecCredential", "spec": spec})
	if err != nil {
		return fail("invalid_kubeconfig")
	}
	environment := map[string]string{}
	// Inherit only host settings needed for normal process and user config
	// discovery. All plugin-provided environment variables were approved.
	for _, key := range []string{"HOME", "USERPROFILE", "SystemRoot", "WINDIR", "TMPDIR", "TEMP", "TMP", "PATH"} {
		if value, found := os.LookupEnv(key); found {
			environment[key] = value
		}
	}
	for _, entry := range p.exec.Env {
		if entry.Name == "" || strings.ContainsAny(entry.Name, "=\x00") || strings.ContainsRune(entry.Value, 0) {
			return fail("invalid_kubeconfig")
		}
		environment[entry.Name] = entry.Value
	}
	environment["KUBERNETES_EXEC_INFO"] = string(request)
	env := make([]string, 0, len(environment))
	for key, value := range environment {
		env = append(env, key+"="+value)
	}
	sort.Strings(env)
	ctx, cancel := context.WithTimeout(ctx, pluginTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, p.path, p.exec.Args...)
	cmd.Env = env
	cmd.WaitDelay = 250 * time.Millisecond
	buf := &pluginBuffer{Buffer: &bytes.Buffer{}}
	cmd.Stdout = buf
	cmd.Stderr = io.Discard
	if err = cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if buf.oversize {
			return fail("output_limit")
		}
		return fail("exec_failed")
	}
	defer clear(buf.Bytes())
	var credential pluginCredential
	if json.Unmarshal(buf.Bytes(), &credential) != nil || credential.Kind != "ExecCredential" ||
		credential.Version != p.exec.APIVersion || credential.Status == nil {
		return fail("exec_invalid_response")
	}
	status := credential.Status
	if (status.Expires != nil && !status.Expires.After(time.Now())) || (status.Token == "" && status.Certificate == "") ||
		((status.Certificate == "") != (status.Key == "")) || strings.ContainsAny(status.Token, "\r\n") {
		return fail("exec_invalid_response")
	}
	cfg.ExecProvider = nil
	cfg.BearerToken = status.Token
	if status.Certificate != "" {
		cfg.CertData = []byte(status.Certificate)
		cfg.KeyData = []byte(status.Key)
	}
	return nil
}

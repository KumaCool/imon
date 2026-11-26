package collector

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/pkg/sftp"
)

type MaintenanceResult struct {
	Status        string `json:"status"`
	Version       string `json:"version,omitempty"`
	Architecture  string `json:"architecture,omitempty"`
	MarkersAbsent bool   `json:"markers_absent,omitempty"`
	StagedPath    string `json:"staged_path,omitempty"`
	SHA256        string `json:"sha256,omitempty"`
}

const FirewallAdministratorRequired = "administrator_required"

var (
	maintenanceUser = regexp.MustCompile("^[a-zA-Z_][a-zA-Z0-9_.-]{0,63}$")
	// Pending maintenance jobs can still refer to an upload created before the rename.
	maintenanceStage = regexp.MustCompile("^/var/tmp/(imon|infra-monitor)-upload[.][a-zA-Z0-9]{8}/firewall-maintain[.]sh$")
	maintenanceHash  = regexp.MustCompile("^[a-f0-9]{64}$")
)

// Do not infer a missing sudoers file if its parent cannot be searched. The
// public files are enough to discover previous releases, not to certify removal.
const inspectFirewallCommand = `LC_ALL=C; export LC_ALL
trusted_dir() {
  dir=$1
  while [ "$dir" != / ]; do
    [ -d "$dir" ] && [ ! -L "$dir" ] && [ "$(/usr/bin/stat -c %u -- "$dir")" = 0 ] || return 1
    mode=$(/usr/bin/stat -c %a -- "$dir") || return 1
    [ "$((0$mode & 022))" = 0 ] || return 1
    dir=${dir%/*}; [ -n "$dir" ] || dir=/
  done
}
absent() {
  p=$1
  while [ "$p" != / ]; do
    [ ! -e "$p" ] && [ ! -L "$p" ] || return 1
    p=${p%/*}; [ -n "$p" ] || p=/
    if [ -e "$p" ] || [ -L "$p" ]; then
      [ -x "$p" ] && trusted_dir "$p"
      return $?
    fi
  done
  return 1
}
temporary_area_clear() {
  area=$1; shift
  if absent "$area"; then return 0; fi
  [ -r "$area" ] && [ -x "$area" ] && trusted_dir "$area" || return 1
  for candidate do
    absent "$candidate" || return 1
  done
}
inspect_layout() {
  state=/var/lib/$1
  lib=/usr/local/libexec/$1
  helper=$lib/firewall-read
  manifest=$state/firewall-manifest.json
  auth_dir=/etc/sudoers.d
  sudoers=$auth_dir/$1-firewall
  if absent "$helper" && absent "$manifest"; then
    if ! absent "$state/firewall.lock" ||
      ! temporary_area_clear "$state" "$state"/.stage.???????? ||
      ! temporary_area_clear "$lib" "$lib"/.reader.????????; then
      printf '%s\n' unknown
    elif absent "$sudoers" && temporary_area_clear "$auth_dir" "$auth_dir"/.$1.????????; then
      printf '%s\n' uninstalled
    elif trusted_dir "$auth_dir" && [ ! -x "$auth_dir" ]; then
      printf '%s\n' markers-absent
    else
      printf '%s\n' unknown
    fi
  elif trusted_dir "$state" && trusted_dir "$lib" &&
    [ -f "$manifest" ] && [ ! -L "$manifest" ] && [ -f "$helper" ] && [ ! -L "$helper" ] &&
    [ "$(/usr/bin/stat -c '%u:%h:%a' -- "$manifest")" = '0:1:600' ] &&
    [ "$(/usr/bin/stat -c '%u:%h:%a' -- "$helper")" = '0:1:755' ]; then
    digest=$(/usr/bin/sha256sum -- "$helper") || return 1
    printf 'installed %s\n' "${digest%% *}"
  else
    printf '%s\n' unknown
  fi
}
current=$(inspect_layout imon) || exit 1
legacy=$(inspect_layout infra-monitor) || exit 1
case "$current:$legacy" in
  'installed '*:uninstalled|'installed '*:markers-absent) printf '%s\n' "$current" ;;
  uninstalled:'installed '*|markers-absent:'installed '*) printf '%s\n' "$legacy" ;;
  uninstalled:uninstalled) printf '%s\n' uninstalled ;;
  markers-absent:markers-absent) printf '%s\n' markers-absent ;;
  *) printf '%s\n' unknown ;;
esac`

const stageOnlyCommand = "set -eu; umask 077; dir=$(/usr/bin/mktemp -d /var/tmp/imon-upload.XXXXXXXX); target=$dir/firewall-maintain.sh; trap 'rm -f -- \"$target\"; rmdir -- \"$dir\"' EXIT; imon_payload > \"$target\"; /usr/bin/chmod 0600 \"$target\"; printf '%s\\n' \"$target\"; trap - EXIT"

const stageSFTPCommand = "set -eu; umask 077; dir=$(/usr/bin/mktemp -d /var/tmp/imon-upload.XXXXXXXX); printf '%s/firewall-maintain.sh\\n' \"$dir\""

func (s *sshConnection) stageWithSFTP(ctx context.Context, script []byte) (string, error) {
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	stop := context.AfterFunc(ctx, s.close)
	defer stop()
	client, err := sftp.NewClient(s.client, sftp.UseConcurrentWrites(true))
	if err != nil {
		return "", fail("sftp_unavailable")
	}
	defer client.Close()
	output, err := s.runLimited(ctx, stageSFTPCommand, 1024)
	if err != nil {
		return "", err
	}
	path := strings.TrimSpace(string(output))
	if !maintenanceStage.MatchString(path) {
		return "", fail("invalid_response")
	}
	file, err := client.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY)
	if err != nil {
		return path, fail("sftp_upload_failed")
	}
	err = file.Chmod(0600)
	if err == nil {
		var n int64
		n, err = io.Copy(file, bytes.NewReader(script))
		if err == nil && n != int64(len(script)) {
			err = io.ErrShortWrite
		}
	}
	closeErr := file.Close()
	if err != nil || closeErr != nil || ctx.Err() != nil {
		return path, fail("sftp_upload_failed")
	}
	return path, nil
}

func firewallArchitecture(ctx context.Context, s *sshConnection) (string, error) {
	data, err := s.runLimited(ctx, "/usr/bin/uname -m", 1024)
	if err != nil {
		return "", err
	}
	switch strings.TrimSpace(string(data)) {
	case "x86_64":
		return "amd64", nil
	case "aarch64":
		return "arm64", nil
	default:
		return "", fail("unsupported_architecture")
	}
}

// FirewallPlatform selects the embedded maintenance script for the
// already-bound Linux host.
func FirewallPlatform(ctx context.Context, cfg Config, identity string) (string, error) {
	if identity == "" {
		return "", fail("identity_changed")
	}
	s, err := Open(ctx, "host", cfg, identity)
	if err != nil {
		return "", err
	}
	defer s.Close()
	return firewallArchitecture(ctx, s.ssh)
}

// DetectFirewall inspects a package already on the host, even if it was
// installed by another panel release. It never uploads or changes files.
func DetectFirewall(ctx context.Context, cfg Config, identity string) (MaintenanceResult, error) {
	return inspectFirewall(ctx, cfg, identity, false)
}

func inspectFirewall(ctx context.Context, cfg Config, identity string, verifyRules bool) (MaintenanceResult, error) {
	result := MaintenanceResult{Status: "unknown"}
	if identity == "" {
		return result, fail("identity_changed")
	}
	s, err := Open(ctx, "host", cfg, identity)
	if err != nil {
		return result, err
	}
	defer s.Close()
	result.Architecture, err = firewallArchitecture(ctx, s.ssh)
	if err != nil && Code(err) != "unsupported_architecture" && Code(err) != "command_unavailable" {
		return result, err
	}
	if _, native, nativeErr := s.ssh.nativeFirewall(ctx); native {
		if nativeErr != nil {
			return result, nativeErr
		}
		result.Status = "native"
		return result, nil
	}
	output, err := s.ssh.runLimited(ctx, inspectFirewallCommand, 1024)
	if err != nil {
		return result, err
	}
	probe := strings.TrimSpace(string(output))
	switch probe {
	case "uninstalled", "markers-absent":
		result.MarkersAbsent = true
		if probe == "uninstalled" {
			result.Status = probe
		}
	case "unknown":
	default:
		digest, ok := strings.CutPrefix(probe, "installed ")
		if !ok || !maintenanceHash.MatchString(digest) {
			return result, fail("invalid_response")
		}
		// Discovery can recognize a broken reader so it can still be updated.
		if verifyRules {
			rows, err := s.ssh.firewall(ctx)
			if err != nil {
				return result, err
			}
			if len(rows) == 0 {
				return result, fail("result_unconfirmed")
			}
		}
		result.Status, result.Version = "installed", digest
	}
	return result, nil
}

// MaintainFirewall inspects or updates only the embedded maintenance package.
// Staging requires a separate call after the automatic attempt.
func MaintainFirewall(ctx context.Context, cfg Config, admin *Config, expectedIdentity, action string, script []byte) (MaintenanceResult, error) {
	result := MaintenanceResult{}
	if expectedIdentity == "" || !maintenanceUser.MatchString(cfg.SSH.User) || cfg.SSH.User == "root" || (action != "install" && action != "uninstall" && action != "verify") {
		return result, fail("invalid_maintenance")
	}
	if (action != "verify" || admin != nil) && (len(script) == 0 || len(script) > 32<<20) {
		return result, fail("maintenance_package_unavailable")
	}
	if action != "verify" && admin == nil {
		return result, fail(FirewallAdministratorRequired)
	}
	if action == "verify" && admin == nil {
		return inspectFirewall(ctx, cfg, expectedIdentity, true)
	}
	s, err := Open(ctx, "host", cfg, expectedIdentity)
	if err != nil {
		return result, err
	}
	defer s.Close()
	if action == "verify" {
		result.Status = "unknown"
	}
	digest := sha256.Sum256(script)
	result.SHA256 = hex.EncodeToString(digest[:])
	if admin != nil {
		// Connection location and pinned keys come from the existing binding.
		// Administrator credentials can only replace the target login identity.
		privileged := cfg
		privileged.SSH.User = admin.SSH.User
		privileged.SSH.KeyFile = admin.SSH.KeyFile
		if !maintenanceUser.MatchString(privileged.SSH.User) || privileged.SSH.KeyFile == "" || privileged.SSH.User == cfg.SSH.User || privileged.SSH.KeyFile == cfg.SSH.KeyFile {
			return result, fail("invalid_maintenance_credential")
		}
		remote, err := Open(ctx, "host", privileged, expectedIdentity)
		if err != nil {
			if action != "verify" {
				switch Code(err) {
				case "authentication_failed", "credential_unreadable", "credential_invalid", "credential_passphrase_required", "permission_denied", "command_unavailable":
					return result, fail(FirewallAdministratorRequired)
				}
			}
			return result, err
		}
		defer remote.Close()
		launcher := "sudo -n -- "
		privilegeProbe := "sudo -n -- /usr/bin/id -u"
		if privileged.SSH.User == "root" {
			launcher = ""
			privilegeProbe = "/usr/bin/id -u"
		}
		probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		output, probeErr := remote.ssh.runLimited(probeCtx, privilegeProbe, 1024)
		cancel()
		switch Code(probeErr) {
		case "":
			if strings.TrimSpace(string(output)) != "0" {
				if action != "verify" {
					return result, fail(FirewallAdministratorRequired)
				}
				return result, fail("administrator_unverified")
			}
			body := "set -eu; umask 077; dir=$(/usr/bin/mktemp -d /var/tmp/imon-admin.XXXXXXXX); target=$dir/firewall-maintain.sh; trap 'rm -f -- \"$target\"; rmdir -- \"$dir\"' EXIT; /bin/cat > \"$target\"; printf '%s  %s\\n' '" + result.SHA256 + "' \"$target\" | /usr/bin/sha256sum -c - >/dev/null; /bin/sh \"$target\" " + action + " --collector " + cfg.SSH.User
			installCtx, stop := context.WithTimeout(ctx, 2*time.Minute)
			output, runErr := remote.ssh.runInput(installCtx, "imon_payload | "+launcher+"/bin/sh -c "+shellQuote(body), 4096, script)
			stop()
			if runErr != nil {
				result.Status = "unknown"
				return result, runErr
			}
			result.Status = "unknown"
			probe := strings.TrimSpace(string(output))
			if probe == "uninstalled" && (action == "verify" || action == "uninstall") {
				result.Status, result.MarkersAbsent = "uninstalled", true
				if action == "uninstall" {
					result.Status = "verified"
				}
				return result, nil
			}
			if digest, ok := strings.CutPrefix(probe, "installed "); ok && maintenanceHash.MatchString(digest) && (action == "verify" || action == "install") {
				rows, readErr := s.ssh.firewall(ctx)
				if readErr != nil {
					return result, readErr
				}
				if len(rows) == 0 {
					return result, fail("result_unconfirmed")
				}
				result.Status, result.Version = "installed", digest
				if action == "install" {
					result.Status = "verified"
				}
				return result, nil
			}
			return result, fail("result_unconfirmed")
		case "permission_denied", "command_failed", "command_unavailable":
			// The fixed probe cannot change the remote host.
			if action == "verify" {
				return result, probeErr
			}
			return result, fail(FirewallAdministratorRequired)
		default:
			return result, probeErr
		}
	}
	return result, fail(FirewallAdministratorRequired)
}

// StageFirewall uploads the embedded package as the bound collector account.
// It never installs or removes the package.
func StageFirewall(ctx context.Context, cfg Config, expectedIdentity, action string, script []byte) (MaintenanceResult, error) {
	result := MaintenanceResult{}
	if expectedIdentity == "" || !maintenanceUser.MatchString(cfg.SSH.User) || cfg.SSH.User == "root" || (action != "install" && action != "uninstall") {
		return result, fail("invalid_maintenance")
	}
	if len(script) == 0 || len(script) > 32<<20 {
		return result, fail("maintenance_package_unavailable")
	}
	digest := sha256.Sum256(script)
	result.SHA256 = hex.EncodeToString(digest[:])
	uploadCtx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	s, err := Open(uploadCtx, "host", cfg, expectedIdentity)
	if err != nil {
		return result, err
	}
	defer s.Close()
	sftpCtx, endSFTP := context.WithTimeout(uploadCtx, 30*time.Second)
	path, err := s.ssh.stageWithSFTP(sftpCtx, script)
	endSFTP()
	if err == nil {
		result.Status, result.StagedPath = "awaiting_admin", path
		return result, nil
	}
	result.StagedPath = path
	// A stalled subsystem may have closed the transport. Use a fresh pinned
	// session for the fallback and to remove any incomplete private upload.
	s.Close()
	fallback, err := Open(uploadCtx, "host", cfg, expectedIdentity)
	if err != nil {
		return result, err
	}
	defer fallback.Close()
	if path != "" {
		if err := fallback.ssh.clearFirewallStage(uploadCtx, path); err != nil {
			return result, err
		}
		result.StagedPath = ""
	}
	output, err := fallback.ssh.runInput(uploadCtx, stageOnlyCommand, 1024, script)
	if err != nil {
		return result, err
	}
	path = strings.TrimSpace(string(output))
	if !maintenanceStage.MatchString(path) {
		return result, fail("invalid_response")
	}
	result.Status, result.StagedPath = "awaiting_admin", path
	return result, nil
}

func shellQuote(v string) string {
	return "'" + strings.ReplaceAll(v, "'", "'\"'\"'") + "'"
}

// FirewallAdminCommand returns the command to run from /bin/sh after a private
// upload. The trusted digest is checked before running the script.
func FirewallAdminCommand(action, user, path, sha256 string) string {
	if (action != "install" && action != "uninstall") || !maintenanceUser.MatchString(user) || user == "root" || !maintenanceStage.MatchString(path) || len(sha256) != 64 {
		return ""
	}
	if _, err := hex.DecodeString(sha256); err != nil {
		return ""
	}
	const launcher = `if [ "$(/usr/bin/id -u)" -eq 0 ]; then exec /bin/sh -c "$@"; fi; exec sudo -- /bin/sh -c "$@"`
	const body = `set -eu; umask 077; dir=$(/usr/bin/mktemp -d /var/tmp/imon-admin.XXXXXXXX); target=$dir/firewall-maintain.sh; ` +
		`trap 'rm -f -- "$target"; rmdir -- "$dir"' EXIT; ` +
		`runuser -u "$2" -- /bin/cat -- "$3" > "$target"; ` +
		`printf '%s  %s\n' "$4" "$target" | /usr/bin/sha256sum -c -; ` +
		`/bin/sh "$target" "$1" --collector "$2"`
	return "/bin/sh -c " + shellQuote(launcher) + " imon " + shellQuote(body) + " imon " + action + " " + user + " " + path + " " + sha256
}

// CleanFirewallStage removes only an upload previously staged by this package.
func CleanFirewallStage(ctx context.Context, cfg Config, identity, path string) error {
	if identity == "" || !maintenanceStage.MatchString(path) {
		return fail("invalid_maintenance")
	}
	s, err := Open(ctx, "host", cfg, identity)
	if err != nil {
		return err
	}
	defer s.Close()
	return s.ssh.clearFirewallStage(ctx, path)
}

func (s *sshConnection) clearFirewallStage(ctx context.Context, path string) error {
	dir := strings.TrimSuffix(path, "/firewall-maintain.sh")
	command := "dir=" + shellQuote(dir) + "; file=" + shellQuote(path) + "; " +
		"if [ ! -e \"$dir\" ] && [ ! -L \"$dir\" ]; then exit 0; fi; " +
		"[ -d \"$dir\" ] && [ ! -L \"$dir\" ] && /bin/rm -f -- \"$file\" && /usr/bin/rmdir -- \"$dir\""
	_, err := s.runLimited(ctx, command, 1024)
	return err
}

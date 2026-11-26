package httpapi

import (
	"context"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unicode/utf8"
)

const pickerTimeout = 2 * time.Minute

var errPickerUnavailable = errors.New("local file picker unavailable")

func (p *businessAPI) localFilePicker(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodError(w, http.MethodPost)
		return
	}
	if r.ContentLength != 0 {
		writeError(w, http.StatusBadRequest, "invalid_request", "文件选择不接受请求参数。", false)
		return
	}
	select {
	case p.picker <- struct{}{}:
		defer func() { <-p.picker }()
	default:
		writeError(w, http.StatusConflict, "local_picker_busy", "已有文件选择窗口打开。", true)
		return
	}
	// A native dialog can remain open longer than the normal HTTP write timeout.
	controller := http.NewResponseController(w)
	if err := controller.SetWriteDeadline(time.Now().Add(pickerTimeout + 5*time.Second)); err != nil && !errors.Is(err, http.ErrNotSupported) {
		writeError(w, http.StatusServiceUnavailable, "local_picker_unavailable", "打开文件选择窗口失败，请手动输入绝对路径。", true)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), pickerTimeout)
	defer cancel()
	path, err := p.chooseFile(ctx)
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		writeError(w, http.StatusGatewayTimeout, "local_picker_timeout", "文件选择已超时，请重试或手动输入绝对路径。", true)
	case err != nil:
		writeError(w, http.StatusServiceUnavailable, "local_picker_unavailable", "打开文件选择窗口失败，请手动输入绝对路径。", true)
	case path == "":
		w.WriteHeader(http.StatusNoContent)
	default:
		writeJSON(w, http.StatusOK, map[string]string{"path": path})
	}
}

const macFilePicker = `
ObjC.import('AppKit');

function run(argv) {
    const app = $.NSApplication.sharedApplication;
    if (!app.setActivationPolicy($.NSApplicationActivationPolicyAccessory)) {
        throw new Error('A macOS graphical session is required');
    }
    const panel = $.NSOpenPanel.openPanel;
    panel.setTitle('Select SSH private key');
    panel.setCanChooseFiles(true);
    panel.setCanChooseDirectories(false);
    panel.setAllowsMultipleSelection(false);
    panel.setShowsHiddenFiles(true);
    if (argv[0]) {
        panel.setDirectoryURL($.NSURL.fileURLWithPathIsDirectory(argv[0], true));
    }
    panel.setLevel($.NSModalPanelWindowLevel);
    app.activateIgnoringOtherApps(true);
    panel.makeKeyAndOrderFront(null);
    return panel.runModal === $.NSModalResponseOK ? ObjC.unwrap(panel.URL.path) : '';
}
`

const windowsFilePicker = `
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms
$dialog = New-Object System.Windows.Forms.OpenFileDialog
try {
    $dialog.Title = 'Select SSH private key'
    $dialog.CheckFileExists = $true
    $dialog.RestoreDirectory = $true
    if ($HOME) {
        $folder = Join-Path $HOME '.ssh'
        if ([System.IO.Directory]::Exists($folder)) { $dialog.InitialDirectory = $folder }
        else { $dialog.InitialDirectory = $HOME }
    }
    if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
        [Console]::Write($dialog.FileName)
    }
} finally {
    $dialog.Dispose()
}
`

func chooseLocalFile(ctx context.Context) (string, error) {
	var cmd *exec.Cmd
	var cancelExitOne bool
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.CommandContext(ctx, "/usr/bin/osascript", "-l", "JavaScript", "-e", macFilePicker, localFilePickerFolder())
	case "linux":
		if os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
			return "", errPickerUnavailable
		}
		folder := localFilePickerFolder()
		zenity, zenityErr := exec.LookPath("zenity")
		kdialog, kdialogErr := exec.LookPath("kdialog")
		isKDE := strings.Contains(strings.ToLower(os.Getenv("XDG_CURRENT_DESKTOP")), "kde")
		switch {
		case kdialogErr == nil && (isKDE || zenityErr != nil):
			cmd = exec.CommandContext(ctx, kdialog, "--title", "Select SSH private key", "--getopenfilename", folder)
		case zenityErr == nil:
			args := []string{"--file-selection", "--title=Select SSH private key"}
			if folder != "" {
				args = append(args, "--filename="+folder+string(os.PathSeparator))
			}
			cmd = exec.CommandContext(ctx, zenity, args...)
		default:
			return "", errPickerUnavailable
		}
		cancelExitOne = true
	case "windows":
		if !filepath.IsAbs(os.Getenv("SystemRoot")) {
			return "", errPickerUnavailable
		}
		powershell := filepath.Join(os.Getenv("SystemRoot"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
		cmd = exec.CommandContext(ctx, powershell, "-NoLogo", "-NoProfile", "-NonInteractive", "-STA", "-Command", windowsFilePicker)
	default:
		return "", errPickerUnavailable
	}
	out, err := cmd.Output()
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	if err != nil {
		// The Linux dialogs both use status 1 on user cancellation.
		var exit *exec.ExitError
		if cancelExitOne && errors.As(err, &exit) && exit.ExitCode() == 1 && len(exit.Stderr) == 0 {
			return "", nil
		}
		return "", errPickerUnavailable
	}
	return parseLocalFilePath(out)
}

func localFilePickerFolder() string {
	home, err := os.UserHomeDir()
	if err != nil || !filepath.IsAbs(home) {
		return ""
	}
	folder := filepath.Join(home, ".ssh")
	if info, err := os.Stat(folder); err == nil && info.IsDir() {
		return folder
	}
	return home
}

func parseLocalFilePath(out []byte) (string, error) {
	if !utf8.Valid(out) {
		return "", errPickerUnavailable
	}
	path := string(out)
	if runtime.GOOS != "windows" {
		path = strings.TrimSuffix(path, "\n")
	}
	if path == "" {
		return "", nil
	}
	if !filepath.IsAbs(path) || strings.ContainsAny(path, "\x00\r\n") {
		return "", errPickerUnavailable
	}
	if info, err := os.Stat(path); err != nil || !info.Mode().IsRegular() {
		return "", errPickerUnavailable
	}
	return path, nil
}

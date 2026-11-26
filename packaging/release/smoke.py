"""Exercise a native release binary using temporary, isolated data."""

import argparse
import json
import os
from pathlib import Path
import queue
import signal
import subprocess
import tempfile
import threading
from urllib.request import HTTPCookieProcessor, Request, build_opener


def cli(binary, *args, expect=0):
    command = [str(binary), *map(str, args)]
    result = subprocess.run(command, capture_output=True, text=True, timeout=20)
    if result.returncode != expect:
        raise RuntimeError(f"{args[0]} exited {result.returncode}, expected {expect}")
    return result.stdout


class Panel:
    def __init__(self, binary, state, *args, env=None, start_new_session=False):
        creation_flags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
        self.process = subprocess.Popen(
            [str(binary), "--data-dir", str(state), *args],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            creationflags=creation_flags,
            env=env,
            start_new_session=start_new_session,
        )
        self.client = build_opener(HTTPCookieProcessor())

    def __enter__(self):
        try:
            first_line = queue.Queue(maxsize=1)
            threading.Thread(
                target=lambda: first_line.put(self.process.stdout.readline()), daemon=True
            ).start()
            line = first_line.get(timeout=10)
            self.origin = line.strip().removeprefix("Panel URL: ").rstrip("/")
            if not self.origin.startswith("http://127.0.0.1:") or not self.origin.rsplit(":", 1)[1].isdigit():
                raise RuntimeError("Panel did not produce a reusable local URL")
            self.request("POST", "/api/v1/session", {})
        except (OSError, ValueError, RuntimeError, queue.Empty):
            self.stop()
            raise RuntimeError("Release panel startup failed") from None
        return self

    def __exit__(self, *_):
        self.stop()

    def stop(self):
        try:
            if self.process.poll() is None:
                self.process.send_signal(signal.CTRL_BREAK_EVENT if os.name == "nt" else signal.SIGTERM)
            if self.process.wait(timeout=10):
                raise RuntimeError("Release panel did not stop cleanly")
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()
            raise
        finally:
            self.process.stdout.close()

    def request(self, method, path, body=None):
        headers = {"Origin": self.origin, "Content-Type": "application/json"}
        data = None if body is None else json.dumps(body).encode()
        with self.client.open(Request(self.origin + path, data, headers, method=method), timeout=5) as resp:
            return json.load(resp) if resp.headers.get_content_type() == "application/json" else None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("tag")
    options = parser.parse_args()
    binary = options.binary.resolve(strict=True)
    if cli(binary, "--version").strip() != options.tag:
        raise RuntimeError("Release version does not match the requested tag")
    settings = "/api/v1/sampling-settings"
    with tempfile.TemporaryDirectory(prefix="imon-release-") as temporary:
        root = Path(temporary)
        source, target, backup = root / "source", root / "target", root / "snapshot.bak"
        for directory, interval in ((source, 71), (target, 72)):
            with Panel(binary, directory) as panel:
                value = panel.request("GET", settings)
                value.update(poll_enabled=False, host_interval=interval)
                panel.request("PUT", settings, value)
                if panel.request("GET", settings)["host_interval"] != interval:
                    raise RuntimeError("Release settings did not save")
        cli(binary, "--data-dir", source, "--backup", backup)
        original = backup.read_bytes()
        if not original.startswith(b"SQLite format 3\0"):
            raise RuntimeError("CLI did not produce a standalone SQLite backup")
        cli(binary, "--data-dir", source, "--backup", backup, expect=1)
        if backup.read_bytes() != original:
            raise RuntimeError("CLI overwrote the existing backup")
        print("Backup and overwrite rejection passed")
        cli(binary, "--data-dir", target, "--restore", backup)
        (rollback,) = target.glob("state.sqlite3.pre-restore*.bak")
        with Panel(binary, target) as panel:
            current = panel.request("GET", settings)
            if current["host_interval"] != 71 or current["poll_enabled"]:
                raise RuntimeError("Restored settings differ from the backup")
        print("Restore and restart passed (host interval: 71)")
        cli(binary, "--data-dir", target, "--restore", rollback)
        with Panel(binary, target) as panel:
            current = panel.request("GET", settings)
            if current["host_interval"] != 72 or current["poll_enabled"]:
                raise RuntimeError("Rollback settings differ from the original")
        print("Rollback and restart passed (host interval: 72)")


if __name__ == "__main__":
    main()

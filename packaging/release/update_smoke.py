"""Exercise a release binary in an offline Linux container against a local Release fixture."""

import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import ssl
import subprocess
import tarfile
import tempfile
from threading import Thread
import time
from urllib.error import HTTPError, URLError

from smoke import Panel


HOSTS = ("api.github.com", "github.com", "release-assets.githubusercontent.com")
REPO = "fixture/imon"
TAG = "v1.0.1"
ENDPOINT = "/api/v1/version/update"


class FixtureHandler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        host = self.headers.get("Host")
        fixture = self.server
        if host == HOSTS[0] and self.path == f"/repos/{REPO}/releases/latest":
            fixture.checks += 1
            self.reply(200, fixture.metadata, "application/json")
        elif host == HOSTS[1] and self.path == f"/{REPO}/releases/download/{TAG}/{fixture.asset}":
            self.send_response(302)
            self.send_header("Location", f"https://{HOSTS[2]}/fixture/{fixture.asset}")
            self.end_headers()
        elif host == HOSTS[2] and self.path == f"/fixture/{fixture.asset}":
            fixture.downloads += 1
            data = fixture.content if fixture.valid else b"!" + fixture.content[1:]
            self.reply(200, data, "application/octet-stream")
        else:
            self.send_error(404)

    def reply(self, status, body, mime):
        self.send_response(status)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def make_fixture(root, archive):
    cert, key, config = (root / name for name in ("fixture.pem", "fixture.key", "fixture.conf"))
    san = ",".join(f"DNS:{name}" for name in HOSTS)
    config.write_text(f"[req]\ndistinguished_name = dn\nx509_extensions = ext\nprompt = no\n"
                      f"[dn]\nCN = fixture.invalid\n[ext]\nsubjectAltName = {san}\nbasicConstraints = CA:TRUE\n")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-config", config,
                    "-keyout", key, "-out", cert], check=True, capture_output=True)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(cert, key)
    fixture = ThreadingHTTPServer(("127.0.0.1", 443), FixtureHandler)
    fixture.socket = tls.wrap_socket(fixture.socket, server_side=True)
    fixture.asset = archive.name
    set_release(fixture, archive.read_bytes())
    fixture.valid = False
    env = {key: value for key, value in os.environ.items() if not key.lower().endswith("_proxy")}
    env["SSL_CERT_FILE"] = str(cert)
    return fixture, env


def set_release(fixture, content):
    fixture.content = content
    fixture.sha256 = hashlib.sha256(content).hexdigest()
    fixture.metadata = json.dumps({"tag_name": TAG, "name": "Fixture release", "body": "Fixture notes", "assets": [
        {"name": fixture.asset, "digest": f"sha256:{fixture.sha256}", "size": len(content), "state": "uploaded"},
    ]}).encode()
    fixture.checks = fixture.downloads = 0


def check_fixture_network():
    # Linux still lists disabled tunnel devices in some isolated namespaces.
    interfaces = Path("/sys/class/net")
    if not interfaces.is_dir() or any(
        int((interfaces / name / "flags").read_text(), 16) & 1
        for _, name in socket.if_nameindex() if name != "lo"
    ):
        raise RuntimeError("Run inside a Linux container with --network none")
    for host in HOSTS:
        addresses = {entry[4][0] for entry in socket.getaddrinfo(host, 443, family=socket.AF_INET)}
        if addresses != {"127.0.0.1"}:
            raise RuntimeError(f"Add a loopback hosts entry for {host} inside the isolated container")


def exercise(binary, root, fixture, env):
    with Panel(binary, root / "state", "--release-repo", REPO, env=env) as panel:
        local = panel.request("GET", "/api/v1/version")
        if local["state"] != "configured" or local["repository"] != REPO or local["current"] != "v1.0.0":
            raise RuntimeError("Unexpected current release metadata")
        available = panel.request("GET", ENDPOINT)
        if (available["state"], available["tag"], available["asset_name"], available["sha256"]) != (
            "available", TAG, fixture.asset, fixture.sha256,
        ):
            raise RuntimeError("Release API did not select the matching architecture archive")
        request = {"tag": TAG, "sha256": fixture.sha256}
        try:
            panel.request("POST", ENDPOINT, request)
        except HTTPError as error:
            with error:
                if error.code != 502 or json.load(error)["code"] != "checksum_mismatch":
                    raise
        else:
            raise RuntimeError("Tampered update was accepted")
        if list((root / "state" / "updates" / TAG).glob("*")):
            raise RuntimeError("Tampered update left a file")
        fixture.valid = True
        saved = panel.request("POST", ENDPOINT, request)
        if saved["state"] != "downloaded" or Path(saved["path"]).read_bytes() != fixture.content:
            raise RuntimeError("Downloaded release archive differs from fixture")
        repeated = panel.request("POST", ENDPOINT, request)
        if repeated["path"] != saved["path"] or fixture.downloads != 2:
            raise RuntimeError("Verified release archive was not reused")
        if panel.request("GET", "/api/v1/version")["current"] != local["current"]:
            raise RuntimeError("Downloaded release modified the running version")
        print("Release check, HTTPS redirect, tamper rejection, verified staging and reuse passed")


def archive_fixture(name):
    payload = b'''#!/usr/bin/env python3
import os
from pathlib import Path
import sqlite3
import sys

if sys.argv[1:] == ["--version"]:
    print("v1.0.1")
    sys.exit(0)
with sqlite3.connect(Path(sys.argv[2]) / "state.sqlite3") as db:
    db.execute("UPDATE sampling_settings SET host_interval=987")
Path(sys.argv[2], "fixture-startup-failed").touch()
os._exit(42)
'''
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        item = tarfile.TarInfo(name)
        item.size, item.mode = len(payload), 0o755
        archive.addfile(item, io.BytesIO(payload))
    return output.getvalue()


class IsolatedPanel(Panel):
    def stop(self):
        # The update restarts a child in this fixture's private process group.
        try:
            os.killpg(self.process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        super().stop()


def exercise_apply(binary, root, fixture, env, candidate):
    fixture.valid = True
    for label, content, expected_version, expected_state in (
        ("reject", archive_fixture("../imon"), "v1.0.0", "configured"),
        ("install", candidate.read_bytes(), TAG, "configured"),
        ("rollback", archive_fixture("imon"), "v1.0.0", "rolled_back"),
    ):
        work = root / label
        work.mkdir()
        program = work / "imon"
        shutil.copy2(binary, program)
        original = hashlib.sha256(program.read_bytes()).hexdigest()
        set_release(fixture, content)
        # Launch the CLI in a separate process group for reliable update cleanup.
        with IsolatedPanel(program, work / "state", "--release-repo", REPO, env=env, start_new_session=True) as panel:
            settings_path = "/api/v1/sampling-settings"
            settings = panel.request("GET", settings_path)
            settings.update(poll_enabled=False, host_interval=79)
            panel.request("PUT", settings_path, settings)
            checked = panel.request("GET", ENDPOINT + "?startup=1")
            repeated = panel.request("GET", ENDPOINT + "?startup=1")
            if checked != repeated or fixture.checks != 1 or not checked["can_apply"]:
                raise RuntimeError("Startup check was not shared or the build does not support updates")
            if checked.get("release_notes") != "Fixture notes" or not checked.get("release_url", "").endswith(f"/releases/tag/{TAG}"):
                raise RuntimeError("Startup check omitted release information")
            request = {"tag": checked["tag"], "sha256": checked["sha256"]}
            if label == "reject":
                try:
                    panel.request("POST", ENDPOINT + "/apply", request)
                except HTTPError as error:
                    with error:
                        if error.code != 502 or json.load(error)["code"] != "invalid_update_archive":
                            raise
                else:
                    raise RuntimeError("Path traversal was accepted")
            else:
                accepted = panel.request("POST", ENDPOINT + "/apply", request)
                if accepted["state"] != "restarting" or panel.process.wait(timeout=35) != 0:
                    raise RuntimeError("Verified update did not restart cleanly")
                if label == "rollback" and not (work / "state" / "fixture-startup-failed").exists():
                    raise RuntimeError("Failed candidate did not write to the database before rollback")
            for _ in range(10):
                try:
                    got = panel.request("GET", "/api/v1/version")
                    break
                except URLError:
                    time.sleep(0.1)
            else:
                raise RuntimeError("Panel did not return to its existing address")
            if (got["current"], got["state"]) != (expected_version, expected_state) or fixture.checks != 2:
                raise RuntimeError("Unexpected version, rollback result, or release check count")
            current = panel.request("GET", settings_path)
            if current["host_interval"] != 79 or current["poll_enabled"]:
                raise RuntimeError("Update did not preserve panel settings")
            digest = hashlib.sha256(program.read_bytes()).hexdigest()
            if (digest == original) != (label != "install"):
                raise RuntimeError("Unexpected change to the installed executable")
            print(f"{label}: {expected_version} ({expected_state}); same address, session and settings")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--apply-archive", type=Path, help="verified native v1.0.1 archive for testing replacement and rollback")
    args = parser.parse_args()
    check_fixture_network()
    with tempfile.TemporaryDirectory(prefix="imon-release-fixture-") as path:
        root = Path(path)
        fixture, env = make_fixture(root, args.archive)
        with fixture:
            Thread(target=fixture.serve_forever, daemon=True).start()
            try:
                exercise(args.binary.resolve(strict=True), root, fixture, env)
                if args.apply_archive is not None:
                    exercise_apply(args.binary.resolve(strict=True), root, fixture, env, args.apply_archive)
            finally:
                fixture.shutdown()

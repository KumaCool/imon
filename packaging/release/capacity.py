"""Measure service-view collection against authenticated, local Kubernetes API fixtures."""

import argparse
import base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import math
import os
from pathlib import Path
import resource
import signal
import sqlite3
import ssl
import subprocess
import sys
import tempfile
from threading import Lock, Thread
import time
from urllib.parse import parse_qs, urlsplit
from smoke import Panel


TOKEN = "fake-fixture-token"
DATABASE = "state.sqlite3"
COLLECTION_GROUPS = {"deployments"}


class MeasurementPanel(Panel):
    def stop(self):
        try:
            if self.process.returncode is not None:
                return
            pid = self.process.pid
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            deadline = time.monotonic() + 10
            while True:
                finished, status, usage = os.wait4(pid, os.WNOHANG)
                if finished:
                    self.process.returncode = os.waitstatus_to_exitcode(status)
                    self.usage = usage
                    if self.process.returncode != 0:
                        raise RuntimeError("Measurement panel did not stop cleanly")
                    break
                if time.monotonic() >= deadline:
                    self.process.kill()
                    self.process.wait()
                    raise RuntimeError("Measurement panel did not exit")
                time.sleep(0.01)
        finally:
            self.process.stdout.close()


def metadata(name, namespace=None):
    value = {"name": name, "uid": f"fixture-{name}"}
    if namespace:
        value["namespace"] = namespace
    return value


def resources():
    ready = [{"type": "Ready", "status": "True"}]
    data = {
        "/api/v1/namespaces": [{"metadata": metadata(name), "status": {"phase": "Active"}}
                               for name in ("kube-system", "fixture-apps")],
        "/api/v1/nodes": [{"metadata": metadata(f"node-{i}"), "status": {"conditions": ready}} for i in range(3)],
        "/api/v1/pods": [{"metadata": metadata(f"pod-{i}", "fixture-apps"), "spec": {"nodeName": f"node-{i % 3}"},
                          "status": {"phase": "Running", "conditions": ready}} for i in range(100)],
        "/apis/apps/v1/deployments": [],
        "/api/v1/services": [],
        "/apis/discovery.k8s.io/v1/endpointslices": [],
    }
    for i in range(50):
        data["/apis/apps/v1/deployments"].append({
            "metadata": dict(metadata(f"deploy-{i}", "fixture-apps"), generation=1), "spec": {"replicas": 2},
            "status": {"observedGeneration": 1, "replicas": 2, "readyReplicas": 2},
        })
        data["/api/v1/services"].append({
            "metadata": metadata(f"service-{i}", "fixture-apps"),
            "spec": {"type": "ClusterIP", "selector": {"fixture": str(i)}, "ports": [{"port": 8080, "protocol": "TCP"}]},
        })
        data["/apis/discovery.k8s.io/v1/endpointslices"].append({
            "metadata": dict(metadata(f"slice-{i}", "fixture-apps"), labels={"kubernetes.io/service-name": f"service-{i}"}),
            "addressType": "IPv4", "endpoints": [{"addresses": ["192.0.2.1"], "conditions": {"ready": True},
                                                 "targetRef": {"kind": "Pod", "uid": f"fixture-pod-{i}"}}],
        })
    return data


class Fixture(ThreadingHTTPServer):
    def __init__(self, root, delay):
        self.delay = delay
        self.lock = Lock()
        self.started = {}
        self.finished = {}
        self.peak = self.active = 0
        self.measuring = False
        self.resources = resources()
        cert, key = root / "fixture.crt", root / "fixture.key"
        config = root / "fixture-tls.conf"
        config.write_text("[req]\ndistinguished_name = dn\nx509_extensions = ext\nprompt = no\n"
                          "[dn]\nCN = fixture.local\n[ext]\nsubjectAltName = IP:127.0.0.1\nbasicConstraints = CA:TRUE\n")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-config", config,
                        "-keyout", key, "-out", cert], check=True, capture_output=True)
        self.ca = base64.b64encode(cert.read_bytes()).decode()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        super().__init__(("127.0.0.1", 0), Handler)
        self.socket = context.wrap_socket(self.socket, server_side=True)

    def kubeconfig(self, destination, name):
        destination.write_text(json.dumps({
            "apiVersion": "v1", "kind": "Config", "current-context": "fixture",
            "clusters": [{"name": "fixture", "cluster": {"server": f"https://127.0.0.1:{self.server_port}/{name}",
                                                         "certificate-authority-data": self.ca}}],
            "contexts": [{"name": "fixture", "context": {"cluster": "fixture", "user": "fixture"}}],
            "users": [{"name": "fixture", "user": {"token": TOKEN}}],
        }))


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass

    def do_GET(self):
        if self.headers.get("Authorization") != f"Bearer {TOKEN}":
            self.send_error(401)
            return
        parsed = urlsplit(self.path)
        _, name, path = parsed.path.split("/", 2)
        path = "/" + path
        fixture = self.server
        identity = path == "/api/v1/namespaces/kube-system"
        if identity:
            data = {"metadata": {"name": "kube-system", "uid": name}}
        elif path in fixture.resources:
            limit = int(parse_qs(parsed.query).get("limit", ["200"])[0])
            data = {"items": fixture.resources[path][:limit]}
        else:
            self.send_error(404)
            return
        timed = fixture.measuring
        if timed:
            with fixture.lock:
                fixture.active += 1
                fixture.peak = max(fixture.peak, fixture.active)
                if identity:
                    fixture.started[name] = time.time_ns() // 1_000_000
        try:
            response = json.dumps(data, separators=(",", ":")).encode()
            if timed:
                time.sleep(fixture.delay)
                with fixture.lock:
                    fixture.finished[name] = time.time_ns() // 1_000_000
        finally:
            if timed:
                with fixture.lock:
                    fixture.active -= 1
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)


def p95(values):
    return sorted(values)[math.ceil(0.95 * len(values)) - 1]


def measure_wave(panel, fixture, database, targets, measured_jobs):
    with fixture.lock:
        fixture.started.clear()
        fixture.finished.clear()
        fixture.peak = 0
        fixture.measuring = True
    started = time.monotonic()
    names_by_id = {target: name for name, target in targets.items()}
    jobs = {}
    cursor = ""
    while True:
        body = {"view": "services", "source": "cluster"}
        if cursor:
            body["cursor"] = cursor
        started_batch = panel.request("POST", "/api/v1/collection-requests", body)
        for item in started_batch["jobs"]:
            jobs[item["job_id"]] = names_by_id[item["target_id"]]
        cursor = started_batch.get("next_cursor")
        if not cursor:
            break
    if len(jobs) != len(targets) or measured_jobs.intersection(jobs):
        raise RuntimeError("Expected a fresh collection job per target")
    measured_jobs.update(jobs)
    deadline = time.monotonic() + 120
    while True:
        states = database.execute("SELECT job_id,status,queued_at,results FROM collection_jobs").fetchall()
        batch = [row for row in states if row[0] in jobs and row[1] not in ("queued", "running")]
        if len(batch) == len(jobs):
            break
        if time.monotonic() >= deadline:
            raise RuntimeError("Collection did not complete before the measurement timeout")
        time.sleep(0.01)
    elapsed = time.monotonic() - started
    with fixture.lock:
        fixture.measuring = False
        if fixture.peak > 2 or set(fixture.started) != set(targets) or set(fixture.finished) != set(targets):
            raise RuntimeError("Observed fixture traffic does not match the planned wave")
        queue = [max(0, fixture.started[jobs[job]] - queued) for job, _, queued, _ in batch]
        api_span = [fixture.finished[name] - fixture.started[name] for name in targets]
    for _, state, _, raw in batch:
        results = json.loads(raw)
        if state != "success" or set(results) != COLLECTION_GROUPS or any(results.values()):
            raise RuntimeError(f"Collection failed: {state} {raw}")
    published_rows = database.execute("""SELECT COUNT(*) FROM group_state AS g JOIN snapshot_rows AS r
        ON g.target_id=r.target_id AND g.connection_rev=r.connection_rev AND g.group_name=r.group_name
        AND g.published_batch_id=r.batch_id""").fetchone()[0]
    expected_rows = len(jobs) * len(fixture.resources["/apis/apps/v1/deployments"])
    if published_rows != expected_rows:
        raise RuntimeError("Published Kubernetes resources do not match the fixture")
    stored_rows = database.execute("SELECT COUNT(*) FROM snapshot_rows").fetchone()[0]
    if stored_rows != published_rows:
        raise RuntimeError(f"Obsolete snapshot rows accumulated: {stored_rows} stored, {published_rows} published")
    return {"success": len(batch), "wall_s": round(elapsed, 3), "targets_per_s": round(len(batch) / elapsed, 2),
            "queue_p95_ms": p95(queue), "api_span_p95_ms": p95(api_span), "peak_api_requests": fixture.peak,
            "published_rows": published_rows,
            "sqlite_pages": database.execute("PRAGMA page_count").fetchone()[0],
            "sqlite_free_pages": database.execute("PRAGMA freelist_count").fetchone()[0]}


def measure(binary, count, delay):
    with tempfile.TemporaryDirectory(prefix="imon-capacity-") as directory:
        root = Path(directory)
        with Fixture(root, delay) as fixture:
            Thread(target=fixture.serve_forever, daemon=True).start()
            try:
                return run_panel(binary, root, fixture, count)
            finally:
                fixture.shutdown()


def run_panel(binary, root, fixture, count):
    state = root / "state"
    targets = {}
    with Panel(binary, state) as panel:
        settings = panel.request("GET", "/api/v1/sampling-settings")
        settings["poll_enabled"] = False
        panel.request("PUT", "/api/v1/sampling-settings", settings)
        for index in range(count):
            name = f"fixture-cluster-{index}"
            config = root / f"{name}.json"
            fixture.kubeconfig(config, name)
            request = {"kind": "cluster", "name": name, "kubeconfig": str(config), "context": "fixture"}
            probe = panel.request("POST", "/api/v1/targets/test", request)
            if probe["warnings"] or probe["identity"] != name:
                raise RuntimeError("Fixture binding did not verify")
            request["test_token"] = probe["test_token"]
            targets[name] = panel.request("POST", "/api/v1/targets", request)["id"]
    path = state / DATABASE
    with MeasurementPanel(binary, state) as panel:
        database = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)
        try:
            pages = database.execute("PRAGMA page_count").fetchone()[0]
            page_size = database.execute("PRAGMA page_size").fetchone()[0]
            measured_jobs = set()
            waves = [measure_wave(panel, fixture, database, targets, measured_jobs) for _ in range(3)]
        finally:
            database.close()
    usage = panel.usage
    max_rss = usage.ru_maxrss / (1024 if sys.platform == "darwin" else 1)
    return {"clusters": count, "fixture_delay_ms": round(fixture.delay * 1000, 1), "peak_rss_kib": round(max_rss),
            "panel_cpu_s": round(usage.ru_utime + usage.ru_stime, 3), "sqlite_initial_bytes": pages * page_size,
            "sqlite_final_bytes": path.stat().st_size, "sqlite_page_size": page_size, "waves": waves}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("clusters", nargs="*", type=int, default=[12, 48])
    parser.add_argument("--delay-ms", type=float, default=15)
    args = parser.parse_args()
    if any(count <= 0 for count in args.clusters) or not 0 <= args.delay_ms <= 1000:
        parser.error("Cluster counts must be positive and delay must be between 0 and 1000 ms")
    for count in args.clusters:
        print(json.dumps(measure(args.binary.resolve(strict=True), count, args.delay_ms / 1000)), flush=True)

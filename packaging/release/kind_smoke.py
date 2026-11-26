"""Exercise Deployment controls in a disposable local kind cluster."""

import argparse
import ipaddress
import json
from pathlib import Path
import subprocess
import tempfile
import time
from urllib.error import HTTPError
from urllib.parse import urlsplit

from smoke import Panel


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def wait_for(read, ready, description, timeout=75):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        data = read()
        if ready(data):
            return data
        time.sleep(0.25)
    raise RuntimeError(f"Timed out: {description}")


def obj(api, kind, name, **body):
    return dict(apiVersion=api, kind=kind, metadata={"name": name}, **body)


def rule(group, resources, verbs, **fields):
    return dict(apiGroups=[group], resources=resources, verbs=verbs, **fields)


def ref(kind, name):
    return dict(apiGroup="rbac.authorization.k8s.io", kind=kind, name=name)


def exercise(panel, reader, operator, namespace, rollout):
    api = "/api/v1"
    settings_path = f"{api}/sampling-settings"
    panel.request("PUT", settings_path, dict(panel.request("GET", settings_path), poll_enabled=False))
    spec = dict(kind="cluster", name="kind fixture", kubeconfig=str(reader), context="fixture")
    proof = panel.request("POST", f"{api}/targets/test", spec)
    target = panel.request("POST", f"{api}/targets", dict(spec, test_token=proof["test_token"]))
    target_path = f"{api}/targets/{target['id']}"

    def job(job_id, convergence=False):
        def check(value):
            if value["status"] in {"queued", "running"}:
                return False
            require(value["status"] == "success", f"Job failed: {value['status']} {value.get('error_code', '')}")
            if not convergence:
                return True
            state = value["results"].get("convergence")
            require(state in {"pending", "confirmed"}, f"Workload did not converge: {state}")
            return state == "confirmed"

        return wait_for(lambda: panel.request("GET", f"{api}/jobs/{job_id}"), check, "job completion")

    collection = panel.request("POST", f"{api}/collection-requests",
                               dict(view="cluster", group="deployments", target_id=target["id"]))
    require(len(collection["jobs"]) == 1, "Expected one Deployment collection job")
    job(collection["jobs"][0]["job_id"])
    services = panel.request("GET", f"{api}/services?source=cluster&namespace={namespace}")["items"]
    require(len(services) == 1 and services[0]["name"] == "fixture", "Fixture Deployment not listed")
    service = services[0]
    service_path = f"{api}/services/{service['id']}"
    actions_path = f"{service_path}/actions"
    stop = dict(action="stop", connection_rev=service["connection_rev"], expected_state="running", expected_desired=2)
    try:
        panel.request("POST", actions_path, stop)
    except HTTPError as exc:
        require(exc.code == 403, f"Unexpected no-grant status: {exc.code}")
        exc.close()
    else:
        raise RuntimeError("Stop was accepted without a grant")
    print("Manual Deployment collection passed; no-grant stop returned HTTP 403")

    panel.request("PUT", f"{target_path}/service-authorization", dict(
        connection_rev=service["connection_rev"], object_ids=[service["id"]], external_manager_checked=True,
        credential_ref=dict(kubeconfig=str(operator), context="fixture")))
    for command, desired, state, resume in ((stop, 0, "stopped", 2), (
        dict(stop, action="start", expected_state="stopped", expected_desired=0), 2, "running", None,
    )):
        result = job(panel.request("POST", actions_path, command)["job_id"], convergence=True)
        require(result["results"]["observed_state"] == state, "Unexpected convergence state")
        wait_for(lambda: panel.request("GET", service_path),
                 lambda v: v["state"] == state and v["desired"] == desired and v.get("resume_replicas") == resume,
                 "automatic service snapshot refresh")
        observed = rollout()
        require(observed["spec"]["replicas"] == desired and observed["status"].get("readyReplicas", 0) == desired,
                "Cluster replicas differ from the panel")
        print(f"{command['action']}: convergence=confirmed, state={state}, desired={desired}, ready={desired}, resume={resume}")
    panel.request("DELETE", target_path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("kubeconfig", type=Path)
    parser.add_argument("--image", default="alpine:3.20", help="Fixture image with /bin/sh; preload it in kind")
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    config = args.kubeconfig.resolve(strict=True)

    def kubectl(*parts, body=None):
        result = subprocess.run(["kubectl", "--kubeconfig", str(config), *parts], text=True, capture_output=True,
                                input=None if body is None else json.dumps(body), timeout=120)
        require(result.returncode == 0, f"kubectl {parts[0]} failed (exit {result.returncode})")
        return result.stdout.strip()

    data = json.loads(kubectl("config", "view", "--raw", "--minify", "--flatten", "-o", "json"))
    cluster = data["clusters"][0]["cluster"]
    server = urlsplit(cluster["server"])
    require(data["current-context"].startswith("kind-") and server.scheme == "https"
            and server.hostname is not None and ipaddress.ip_address(server.hostname).is_loopback,
            "Use a disposable local kind cluster with a loopback API address")
    cluster = {key: cluster[key] for key in ("server", "certificate-authority-data")}
    rbac = "rbac.authorization.k8s.io/v1"
    namespace = json.loads(kubectl("create", "-f", "-", "-o", "json", body=dict(
        apiVersion="v1", kind="Namespace", metadata={"generateName": "imon-smoke-"})))
    ns = namespace["metadata"]["name"]
    cleanup = []

    def create(value, cluster_scoped=False):
        kubectl("create", "-f", "-", *([] if cluster_scoped else ["-n", ns]), body=value)
        if cluster_scoped:
            cleanup.append((value["kind"].lower(), value["metadata"]["name"]))

    try:
        for name in ("reader", "operator"):
            create(obj("v1", "ServiceAccount", name))
        create(obj(rbac, "ClusterRole", ns, rules=[
            rule("", ["namespaces"], ["get"], resourceNames=["kube-system"])]), True)
        create(obj(rbac, "ClusterRoleBinding", ns, roleRef=ref("ClusterRole", ns), subjects=[
            dict(kind="ServiceAccount", name=name, namespace=ns) for name in ("reader", "operator")]), True)
        read_role = f"{ns}-reader"
        create(obj(rbac, "ClusterRole", read_role, rules=[rule("apps", ["deployments"], ["list"]),
                   rule("", ["nodes", "namespaces", "pods", "services"], ["list"]),
                   rule("discovery.k8s.io", ["endpointslices"], ["list"])]), True)
        create(obj(rbac, "ClusterRoleBinding", read_role, roleRef=ref("ClusterRole", read_role), subjects=[
            dict(kind="ServiceAccount", name="reader", namespace=ns)]), True)
        create(obj(rbac, "Role", "operator", rules=[rule("apps", ["deployments"], ["get"], resourceNames=["fixture"]),
                   rule("apps", ["deployments/scale"], ["get", "update"], resourceNames=["fixture"]),
                   rule("autoscaling", ["horizontalpodautoscalers"], ["list"])]))
        create(obj(rbac, "RoleBinding", "operator", roleRef=ref("Role", "operator"),
                   subjects=[dict(kind="ServiceAccount", name="operator", namespace=ns)]))
        labels = {"app": "imon-fixture"}
        create(obj("apps/v1", "Deployment", "fixture", spec=dict(replicas=2, selector={"matchLabels": labels},
                   template=dict(metadata={"labels": labels}, spec={"containers": [dict(
                       name="fixture", image=args.image, command=["/bin/sh", "-c", "exec sleep 600"])]}))))
        kubectl("rollout", "status", "-n", ns, "deployment/fixture", "--timeout=100s")
        with tempfile.TemporaryDirectory(prefix="imon-kind-") as temporary:
            root = Path(temporary)
            for name in ("reader", "operator"):
                token = kubectl("create", "token", name, "-n", ns, "--duration=15m")
                output = root / f"{name}.json"
                output.touch(mode=0o600)
                output.write_text(json.dumps(dict(apiVersion="v1", kind="Config", **{"current-context": "fixture"},
                    clusters=[dict(name="fixture", cluster=cluster)],
                    contexts=[dict(name="fixture", context={"cluster": "fixture", "user": name})],
                    users=[dict(name=name, user={"token": token})])))
            with Panel(binary, root / "state") as panel:
                exercise(panel, root / "reader.json", root / "operator.json", ns,
                         lambda: json.loads(kubectl("get", "deployment", "fixture", "-n", ns, "-o", "json")))
    finally:
        for kind, name in [*reversed(cleanup), ("namespace", ns)]:
            kubectl("delete", kind, name, "--ignore-not-found", "--wait=false")


if __name__ == "__main__":
    main()

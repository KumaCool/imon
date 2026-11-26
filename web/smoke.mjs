import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { checkListLayout, checkViewportLists } from "./list-layout-checks.mjs";

const chrome = process.env.CHROME_BIN;
if (!chrome) throw new Error("Set CHROME_BIN to a Chromium or Google Chrome executable.");
const assets = Object.fromEntries(await Promise.all(
  ["index.html", "app.css", "app.js"].map(async (name) => [name, await readFile(new URL(name, import.meta.url))]),
));
const host = { id: "host-fixture", kind: "host", name: "测试主机", address: "192.0.2.10", connection_rev: 1, connection_status: "success", stale: true,
  firewall_authorization_status: "uninstalled" };
const cluster = { id: "cluster-fixture", kind: "cluster", name: "测试集群", connection_rev: 1 };
const service = {
  id: "service-fixture", target_id: host.id, target_name: host.name, name: "fixture.service",
  unit: "fixture.service", source: "host", state: "running", connection_rev: 1, authorized: true,
  cpu_percent: 0, memory_bytes: 2048,
};
const deployment = {
  id: "deployment-fixture", target_id: cluster.id, target_name: cluster.name, name: "fixture-deployment",
  uid: "deployment-uid", source: "cluster", namespace: "fixture", state: "stopped", ready: 0, desired: 0,
  authorized: true, connection_rev: 1,
};
const at = Date.now();
host.summary = {
  host_usage: {
    cpu: { used_cores: 0, total_cores: 4, percent: 0 },
    memory: { used_bytes: 1024 ** 3, total_bytes: 4 * 1024 ** 3, percent: 25 },
  },
  os_info: { display_name: "Fixture Linux 12", stale: true },
  service_observation: { observed_at: at, has_items: true },
};
cluster.summary = { service_observation: { observed_at: at, has_items: true } };
const selector = { target_id: host.id, metric: "systemd_state", unit: service.unit };
const event = {
  id: "event-fixture", severity: "warning", status: "active", rule_name: "测试规则", target_id: host.id,
  target_name: host.name, object_name: service.name, panel_revision: 3, panel_read_revision: 1,
  condition: { op: "eq", value: "failed" }, latest_value: "failed", triggered_at: at,
  selector, source_available: true, deliveries: [{ phase: "trigger", channel: "panel", status: "delivered" }],
};
const collectionEvent = {
  id: "collection-event-fixture", source: "collection", group: "routes", error_category: "timed_out",
  severity: "warning", status: "active", target_id: host.id, target_name: host.name,
  triggered_at: at, observed_at: at + 10, source_available: true, deliveries: [],
};
const targets = [host, cluster];
const requests = [];
const rules = [];
const settings = { poll_enabled: true, host_interval: 60, network_interval: 300, cluster_interval: 60, timeout: 45, revision: 1 };
const channels = { panel: true, telegram: false, email: false };
const unconfirmed = { code: "result_unconfirmed", message: "上一项远端操作结果待核实" };
const execDigest = "a".repeat(64);
const release = { current: "v1.1.0", repository: "fixture/imon", tag: "v1.2.0", state: "available",
  release_url: "https://github.com/fixture/imon/releases/tag/v1.2.0", release_name: "Fixture release",
  release_notes: "<em>Plain release notes</em>", can_apply: true,
  asset_name: "imon-web_linux_amd64.tar.gz", size: 4096, sha256: "b".repeat(64) };
const list = (items, fields) => ({ items, ...fields });
const snapshot = (rows) => list(rows.map(([object_key, payload]) => ({ object_key, payload })), {
  observed_at: at, attempt: { status: "ok" },
});
const unread = () => Number(event.panel_revision > event.panel_read_revision);
let convergencePolls = 0;
let documents = 0;
let startupChecks = 0;
let startupChecked = false;
let updateApplied = false;
let pickerCalls = 0;
let requireSession = false;
let collectionJobs = false;
let collectionJobState = "running";
let allowNetworkStatus;
let allowServiceCollection;
let routeDueAt = 0;
let routeRound = 0;
let bindingPagination = false;
let showCollectionEvent = false;
let initialHostCollection = false;
let hostBindingJobState = "running";
const oldFirewallVersion = "a".repeat(64);
const newFirewallVersion = "b".repeat(64);
let firewallVersion = oldFirewallVersion;
let firewallReachable = true;
let firewallUninstalled = false;
let uninstallCommandApplied = false;
let installPendingVerification = false;
let serviceCollectionProblem;
const server = createServer(async (request, response) => {
  const url = new URL(request.url, "http://127.0.0.1");
  const path = url.pathname;
  const method = request.method;
  const q = url.searchParams;
  const json = (value, code = 200) => {
    response.writeHead(code, { "Content-Type": "application/json" });
    response.end(JSON.stringify(value));
  };
  if (!path.startsWith("/api/v1/")) {
    if (path === "/") documents += 1;
    const fixture = {
      "/": ["index.html", "text/html"],
      "/app.js": ["app.js", "text/javascript"],
      "/app.css": ["app.css", "text/css"],
    }[path];
    if (!fixture) return response.writeHead(404).end();
    response.writeHead(200, {
      "Content-Type": fixture[1],
      "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; form-action 'none'",
    });
    return response.end(assets[fixture[0]]);
  }
  const chunks = [];
  for await (const chunk of request) chunks.push(chunk);
  const body = chunks.length ? JSON.parse(Buffer.concat(chunks)) : null;
  requests.push({ path, method, query: Object.fromEntries(q), body });
  if (path === "/api/v1/session") {
    if (method !== "POST" || !body || Object.keys(body).length) return json({ message: "Incorrect session request" }, 400);
    requireSession = false;
    return response.writeHead(204).end();
  }
  if (requireSession) return json({ code: "session_required" }, 401);
  if (path === "/api/v1/collection-requests") {
    if (body.group === "routes") {
      if (body.due_only) assert.ok(Date.now() >= routeDueAt, "automatic route collection must be due");
      routeDueAt = Date.now() + 3000;
      return json({ jobs: [{ job_id: `fixture-route-${++routeRound}` }] }, 202);
    }
    if (initialHostCollection && body.view === "hosts") {
      const target = targets.find((entry) => entry.name === "新测试主机");
      if (target) return json({ jobs: [{ target_id: target.id, job_id: "new-host-collection" }] }, 202);
    }
    if (collectionJobs && body.view === "services" && body.source === "host") {
      if (!body.cursor && allowServiceCollection) await allowServiceCollection;
      const id = body.cursor ? "fixture-collection-3" : "fixture-collection-1";
      return json({
        jobs: [{ target_id: host.id, job_id: id }, { target_id: host.id, job_id: id },
          ...(body.cursor ? [] : [{ target_id: host.id, job_id: "fixture-collection-2" }])],
        ...(body.cursor ? {} : { next_cursor: "fixture-next" }),
      }, 202);
    }
    return json({ jobs: [] });
  }
  if (path === "/api/v1/collection-status") {
    const group = q.get("group");
    if (group === "interfaces" && allowNetworkStatus) await allowNetworkStatus;
    const now = Date.now();
    const finishedHostBatches = q.get("view") === "services" && q.get("source") === "host"
      && collectionJobState === "finished" && requests.some(({ body }) => body?.cursor === "fixture-next");
    return json({
      server_now: now,
      foreground_due: group === "routes" ? now >= routeDueAt : !finishedHostBatches,
      next_foreground_at: group === "routes" && now < routeDueAt ? routeDueAt : null,
      next_run_at: group === "listeners" || (q.get("view") === "services" && q.get("source") === "host") ? now + 90000 : null,
      active: group === "interfaces" && collectionJobs ? { completed: 1, total: 2 } : null,
    });
  }
  if (path.startsWith("/api/v1/jobs/fixture-collection-")) {
    return json({ status: collectionJobState === "finished" ? path.endsWith("-1") ? "failed" : "canceled" : collectionJobState });
  }
  if (path === "/api/v1/jobs/new-host-collection") return json({ status: hostBindingJobState });
  if (path.startsWith("/api/v1/jobs/fixture-route-")) return json({ status: "success" });
  if (path === "/api/v1/local/file-picker") {
    pickerCalls += 1;
    if (pickerCalls === 2) return response.writeHead(204).end();
    if (pickerCalls >= 3) await new Promise((resolve) => setTimeout(resolve, 800));
    return json({ path: pickerCalls === 5 ? "/<FIXTURE>" : "/<FIXTURE_KEY>" });
  }
  if (path === "/api/v1/services") {
    if (serviceCollectionProblem) return json(list([]));
    const filtered = [service, deployment].filter((item) => (!q.has("source") || item.source === q.get("source"))
      && (!q.has("host_id") || item.target_id === q.get("host_id"))
      && (!q.has("q") || item.name.includes(q.get("q"))));
    const field = { name: "name", target: "target_name", state: "state", cpu: "cpu_percent", memory: "memory_bytes" }[q.get("sort")] || "name";
    const order = q.get("direction") === "desc" ? -1 : 1;
    filtered.sort((a, b) => a[field] === b[field] ? 0 : a[field] == null ? 1 : b[field] == null ? -1 : (a[field] < b[field] ? -1 : 1) * order);
    return json(list(filtered));
  }
  if (path === "/api/v1/services/service-fixture") return json(service);
  if (path === "/api/v1/services/service-fixture/actions") {
    if (body.confirm_unknown !== true) return json(unconfirmed, 409);
    return json({ job_id: "job-fixture" }, 202);
  }
  if (path === "/api/v1/jobs/job-fixture") return json({ job_id: "job-fixture", status: "success", results: { systemd: "" } });
  if (path === `/api/v1/services/${deployment.id}`) return json(deployment);
  if (path === `/api/v1/services/${deployment.id}/actions`) return json({ job_id: "scale-fixture" }, 202);
  if (path === "/api/v1/jobs/scale-fixture") {
    convergencePolls += 1;
    const pending = convergencePolls === 1;
    if (!pending) Object.assign(deployment, { state: "running", ready: 1, desired: 1 });
    return json({ job_id: "scale-fixture", status: "success", results: {
      convergence: pending ? "pending" : "confirmed", observed_state: pending ? "starting" : "running",
    } });
  }
  if (path === `/api/v1/hosts/${host.id}/firewall-authorization`) {
    return json({ status: firewallVersion ? "installed" : "uninstalled",
      installed_display_version: firewallVersion ? `v0.1.0 ${firewallVersion.slice(0, 5)}` : "",
      available_display_version: "v0.1.0 bbbbb",
      update_available: Boolean(firewallVersion) && firewallVersion !== newFirewallVersion,
      firewall_authorization_status: host.firewall_authorization_status });
  }
  if (path === `/api/v1/hosts/${host.id}/firewall-maintenance`) {
    if (body.action === "verify") {
      const cleanup = uninstallCommandApplied && Boolean(body.credential_ref);
      const installation = installPendingVerification;
      if (cleanup) firewallUninstalled = true;
      installPendingVerification = false;
      return json({ job_id: cleanup ? "verify-uninstalled-fixture"
        : installation ? "verify-installed-fixture" : "verify-fixture" }, 202);
    }
    if (body.action === "install") return json({ job_id: "firewall-install-fixture" }, 202);
    if (body.credential_ref) {
      firewallVersion = "";
      firewallUninstalled = true;
      return json({ job_id: "firewall-uninstall-admin-fixture" }, 202);
    }
    return json({ job_id: "firewall-uninstall-fixture" }, 202);
  }
  if (path === "/api/v1/jobs/firewall-install-fixture") {
    return json({ job_id: path.split("/").at(-1), status: "failed", error_code: "administrator_required", manual_upload_available: true });
  }
  if (path === "/api/v1/jobs/firewall-install-upload-fixture") {
    return json({ job_id: path.split("/").at(-1), status: "awaiting_admin", stage_path: "/<STAGE>/firewall-maintain.sh",
      sha256: "c".repeat(64), command: "sudo -- /bin/sh '/<STAGE>/firewall-maintain.sh install'", download_path: "/api/v1/jobs/firewall-install-upload-fixture/firewall-script" });
  }
  if (path === "/api/v1/jobs/verify-installed-fixture") {
    host.firewall_authorization_status = "installed";
    return json({ job_id: path.split("/").at(-1), status: "success", results: { firewall_status: "installed", installed_version: newFirewallVersion } });
  }
  if (path === "/api/v1/jobs/firewall-uninstall-admin-fixture") {
    host.firewall_authorization_status = "uninstalled";
    return json({ job_id: path.split("/").at(-1), status: "success", results: { firewall_status: "uninstalled", cleanup_confirmed: "true" } });
  }
  if (path === "/api/v1/jobs/firewall-uninstall-fixture") {
    return json({ job_id: path.split("/").at(-1), status: "failed", error_code: "administrator_required", manual_upload_available: true });
  }
  if (path === "/api/v1/jobs/unbind-offline-fixture") return json({ status: "failed", error_code: "connection_failed" });
  if (path === "/api/v1/jobs/unbind-clean-fixture") {
    targets.splice(targets.indexOf(host), 1);
    firewallVersion = "";
    return json({ status: "success", results: { unbound: "true", firewall_status: "uninstalled", cleanup_confirmed: "true" } });
  }
  if (path === `/api/v1/targets/${host.id}/maintenance/upload` && method === "POST") {
    if (body.action === "install") installPendingVerification = true;
    return json({ job_id: body.action === "install" ? "firewall-install-upload-fixture" : "firewall-upload-fixture" }, 202);
  }
  if (path === "/api/v1/jobs/firewall-upload-fixture") {
    return json({ job_id: "firewall-upload-fixture", status: "awaiting_admin", stage_path: "/<STAGE>/firewall-maintain.sh",
      sha256: "c".repeat(64), command: "sudo -- /bin/sh '/<STAGE>/firewall-maintain.sh'", download_path: "/api/v1/jobs/firewall-upload-fixture/firewall-script" });
  }
  if (path === "/api/v1/jobs/verify-fixture") {
    return json({ job_id: "verify-fixture", status: "success", results: { firewall_status: "installed" } });
  }
  if (path === "/api/v1/jobs/verify-uninstalled-fixture") {
    return json({ job_id: "verify-uninstalled-fixture", status: "success",
      results: { firewall_status: "uninstalled", cleanup_confirmed: "true" } });
  }
  if (path === "/api/v1/targets/test") {
    if (body.kind === "host") {
      if (body.ssh.address === "192.0.2.99") return json({ code: "host_key_changed", message: "SSH 主机身份已变化" }, 409);
      if (body.ssh.key_file.endsWith(".pub")) return json({ code: "credential_invalid", message: "连接测试失败（credential_invalid）" }, 400);
      if (!body.ssh_confirmation_token) return json({ code: "host_key_confirmation_required", details: {
        role: "jump", address: "192.0.2.11:22", fingerprint: "SHA256:fixture-jump", confirmation_token: "jump-token",
      } }, 409);
      if (body.ssh_confirmation_token === "jump-token") return json({ code: "host_key_confirmation_required", details: {
        role: "target", address: "192.0.2.10:22", fingerprint: "SHA256:fixture-host", confirmation_token: "host-token",
      } }, 409);
      return json({ test_token: "host-ticket" });
    }
    if (body.context === "fixture-exec" && body.kube_exec_sha256 !== execDigest) {
      return json({ code: "exec_approval_required", message: "需要确认登录插件" }, 422);
    }
    return json({ test_token: body.context?.startsWith("edit-") ? `ticket-${body.context}` : "fixture-ticket" });
  }
  if (path === "/api/v1/targets/kube-exec-approval") return json({ sha256: execDigest });
  if (path === `/api/v1/targets/${cluster.id}` && method === "GET") {
    return json({ ...cluster, config: { kubeconfig: "/<FIXTURE>", context: "fixture-context" } });
  }
  if (path === `/api/v1/targets/${cluster.id}` && method === "PATCH") {
    if (body.test_token !== `ticket-${body.context}`) return json({ code: "test_required" }, 409);
    if (body.confirm_unknown !== true) return json(unconfirmed, 409);
    Object.assign(cluster, { name: body.name, connection_rev: body.connection_rev + 1 });
    return json(cluster);
  }
  if (path === `/api/v1/targets/${host.id}` && method === "DELETE") {
    if (q.get("confirm_unknown") !== "true") return json(unconfirmed, 409);
    return json({ job_id: !firewallReachable ? "unbind-offline-fixture" : firewallUninstalled ? "unbind-clean-fixture" : "firewall-uninstall-fixture" }, 202);
  }
  if (path === "/api/v1/targets") {
    if (method === "POST") {
      if (body.kind === "host" && body.test_token !== "host-ticket") return json({ code: "test_required" }, 409);
      const saved = { ...(body.kind === "host" ? host : cluster), id: `new-fixture-${targets.length}`, name: body.name };
      targets.push(saved);
      return json(saved, 201);
    }
    if (bindingPagination && q.get("kind") === "host" && q.get("limit") === "50") {
      if (q.get("cursor") === "fixture-binding-next") return json(list([{ ...host, id: "host-page-two", name: "第二页主机" }]));
      return json(list([host], { next_cursor: "fixture-binding-next" }));
    }
    return json(list(targets.filter((target) => !q.has("kind") || target.kind === q.get("kind"))));
  }
  if (path === "/api/v1/sampling-settings") {
    if (method === "PUT") Object.assign(settings, body);
    return json(settings);
  }
  if (path === "/api/v1/hosts/host-fixture/metrics") return json({
    ...snapshot([
      ["cpu", { cpu_percent: 12 }], ["memory", { memory_percent: 23 }],
      ["disk:/", { mountpoint: "/", used_bytes: 2048, total_bytes: 4096, disk_percent: 50 }],
      ["network:fixture-if", { interface: "fixture-if", rx_bytes_per_second: 1024, tx_bytes_per_second: 2048 }],
    ]),
    history: [30, 29, 23, 22].map((minutes, index) => ({ metric: "cpu_percent", at: at - minutes * 60000, value: 10 + index })),
  });
  if (path === "/api/v1/hosts/host-fixture/network/interfaces") return json(snapshot([
    ["fixture-if", { name: "fixture-if", state: "UP", mtu: 1500, addresses: [{ local: "192.0.2.10", prefixlen: 24 }] }],
  ]));
  if (path === "/api/v1/hosts/host-fixture/network/listeners") return json(snapshot([
    ["fixture-port", { protocol: "tcp", address: "192.0.2.10", port: 8080, process_state: "unreadable" }],
  ]));
  if (path === "/api/v1/hosts/host-fixture/network/routes") return json(snapshot([
    ["fixture-route", { destination: "192.0.2.0/24", dev: "fixture-if" }],
  ]));
  if (path === "/api/v1/hosts/host-fixture/network/firewall") return json(snapshot([
    ["ufw", { backend: "ufw", status: "ok", format: "text",
      payload: "Status: active\nDefault: deny (incoming)\n\nTo  Action  From\n--  ------  ----\n8080/tcp  ALLOW IN  192.0.2.0/24" }],
    ["nftables", { backend: "nftables", status: "ok", format: "json", payload: { nftables: [
      { chain: { family: "inet", table: "fixture-table", name: "fixture-input", policy: "drop" } },
      { rule: { family: "inet", table: "fixture-table", chain: "fixture-input", expr: [
        { match: { left: { meta: { key: "l4proto" } }, op: "==", right: "tcp" } }, { accept: null },
      ] } },
    ] } }],
    ["iptables-legacy", { backend: "iptables-legacy", status: "ok", format: "families", payload: {
      ipv4: { status: "ok", payload: "*filter\n:INPUT ACCEPT [0:0]\n-A INPUT -s 192.0.2.0/24 -m comment --comment \"-j fixture\" -j DROP\nCOMMIT" },
      ipv6: { status: "not_installed", error_code: "not_installed" },
    } }],
  ]));
  if (path === "/api/v1/alert-events") return json(list(q.get("unread") === "true" && !unread() ? []
    : showCollectionEvent ? [collectionEvent, event] : [event], { unread_count: unread() }));
  if (path === `/api/v1/alert-events/${collectionEvent.id}`) return json(collectionEvent);
  if (path === "/api/v1/alert-events/event-fixture") return json(event);
  if (path === "/api/v1/alert-events/event-fixture/read") {
    event.panel_read_revision = body.through_revision;
    return json({ id: event.id, unread_count: unread() });
  }
  if (path === "/api/v1/alert-rules") {
    if (method === "POST") rules.push({ ...body, id: "rule-fixture", revision: 1 });
    return json(list(rules), method === "POST" ? 201 : 200);
  }
  if (path === "/api/v1/notification-targets") return json(list([]));
  if (path === "/api/v1/notification-settings/panel/test") return json({ result: "delivered" });
  if (path === "/api/v1/notification-settings") {
    if (method === "PUT") Object.assign(channels, body);
    return json(channels);
  }
  if (path === "/api/v1/version") return json({ current: updateApplied ? release.tag : release.current, repository: release.repository, state: "configured" });
  if (path === "/api/v1/version/update") {
    assert.equal(q.get("startup"), "1");
    if (!startupChecked) ++startupChecks;
    startupChecked = true;
    return json(updateApplied ? { current: release.tag, state: "up_to_date" } : release);
  }
  if (path === "/api/v1/version/update/apply" && method === "POST") {
    updateApplied = true;
    startupChecked = false;
    return json({ state: "restarting" }, 202);
  }
  return json({ message: "Fixture route missing" }, 404);
});

await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
const url = `http://127.0.0.1:${server.address().port}`;
const profile = await mkdtemp(join(tmpdir(), "imon-web-"));
const browser = spawn(chrome, ["--headless=new", "--disable-gpu", "--disable-background-networking",
  "--no-first-run", "--remote-debugging-port=0", `--user-data-dir=${profile}`, "about:blank"],
{ stdio: ["ignore", "ignore", "pipe"] });
const browserExit = once(browser, "exit");
let socket;

async function retry(run, name, attempts = 120) {
  let error;
  for (let i = 0; i < attempts; i += 1) {
    try {
      if (await run()) return;
    } catch (failure) {
      error = failure;
    }
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error(`Timed out: ${name}`, { cause: error });
}

try {
  let stderr = "";
  browser.stderr.on("data", (data) => { stderr += data; });
  let protocolURL;
  await retry(async () => {
    if (browser.exitCode !== null) throw new Error(stderr);
    const reported = await readFile(join(profile, "DevToolsActivePort"), "utf8");
    const port = Number(reported.split("\n")[0]);
    if (!Number.isInteger(port) || port <= 0) return false;
    const tabs = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
    protocolURL = tabs.find((tab) => tab.type === "page")?.webSocketDebuggerUrl;
    return Boolean(protocolURL);
  }, "browser startup", 400);
  socket = new WebSocket(protocolURL);
  await once(socket, "open");
  let commandID = 0;
  const pending = new Map();
  const browserErrors = [];
  socket.addEventListener("message", ({ data }) => {
    const message = JSON.parse(data);
    if (message.method === "Runtime.exceptionThrown") browserErrors.push(message.params.exceptionDetails.text);
    const resolve = pending.get(message.id);
    if (resolve) {
      pending.delete(message.id);
      resolve(message);
    }
  });
  const call = (method, params = {}) => new Promise((resolve, reject) => {
    const id = ++commandID;
    const timer = setTimeout(() => { pending.delete(id); reject(new Error(`CDP timed out: ${method}`)); }, 5000);
    pending.set(id, (message) => {
      clearTimeout(timer);
      if (message.error) reject(new Error(message.error.message));
      else resolve(message.result);
    });
    socket.send(JSON.stringify({ id, method, params }));
  });
  await call("Runtime.enable");
  await call("Page.enable");
  const evaluate = async (expression) => {
    const answer = await call("Runtime.evaluate", { expression, returnByValue: true });
    if (answer.exceptionDetails) throw new Error(answer.exceptionDetails.exception?.description || answer.exceptionDetails.text);
    return answer.result.value;
  };
  const waitText = (selector, value) => retry(() => evaluate(
    `document.querySelector(${JSON.stringify(selector)})?.textContent.includes(${JSON.stringify(value)})`,
  ), `${selector} contains ${value}`);
  const clickText = (selector, label) => retry(() => evaluate(
    `(() => {
      const nodes = document.querySelectorAll(${JSON.stringify(selector)});
      const node = [...nodes].find(candidate => !candidate.disabled && candidate.textContent.trim() === ${JSON.stringify(label)});
      if (!node || node.closest('[inert]')) return false;
      node.click();
      return true;
    })()`,
  ), `click ${label}`);
  const setField = (selector, value, eventName = "input") => evaluate(
    `(() => { const node = document.querySelector(${JSON.stringify(selector)}); node.value = ${JSON.stringify(value)}; node.dispatchEvent(new Event(${JSON.stringify(eventName)}, { bubbles: true })); })()`,
  );
  const nav = (view) => evaluate(`document.querySelector('[data-nav="${view}"]').click()`);
  const hostAction = async (label) => {
    await evaluate(`(() => {
      const trigger = document.querySelector(".host-row .host-action-trigger");
      if (trigger.getAttribute("aria-expanded") !== "true") trigger.click();
    })()`);
    await clickText(".host-action-menu:not([hidden]) button", label);
  };
  const hostMenu = async () => {
    await clickText(".host-row .host-action-trigger", "操作");
    return evaluate("[...document.querySelectorAll('.host-action-menu:not([hidden]) button')].map(button => button.textContent.trim())");
  };
  const confirmation = "#dialog input[name=confirm_unknown]";
  const clickConfirmation = () => evaluate(`document.querySelector(${JSON.stringify(confirmation)}).click()`);
  const confirmState = () => evaluate(`(() => {
    const input = document.querySelector(${JSON.stringify(confirmation)});
    return { visible: !input.closest('label').hidden, checked: input.checked };
  })()`);
  const isButtonDisabled = (label) => evaluate(`
    [...document.querySelectorAll('#dialog button')].find(button => button.textContent.trim() === ${JSON.stringify(label)}).disabled
  `);
  const assertUnconfirmed = async (label) => {
    await waitText("#dialog", unconfirmed.message);
    assert.deepEqual(await confirmState(), { visible: true, checked: false });
    assert.equal(await isButtonDisabled(label), true);
  };
  const requestsFor = (method, path) => requests.filter((request) => request.method === method && request.path === path);

  await call("Emulation.setDeviceMetricsOverride", { width: 1280, height: 900, deviceScaleFactor: 1, mobile: false });
  await call("Page.navigate", { url });
  await waitText("main.content", host.name);
  assert.equal(await evaluate("document.querySelector('main.content h1').textContent"), "主机管理");
  await waitText("main.content", "Fixture Linux 12");
  assert.deepEqual(await evaluate(`Array.from(document.querySelectorAll('.host-row .resource-usage'), (usage) =>
    Array.from(usage.children, (child) => child.textContent))`), [["0.0%", "0.0 核 / 4.0 核"], ["25.0%", "1.0 GiB / 4.0 GiB"]]);
  assert.deepEqual(await evaluate("[...document.querySelectorAll('main th')].map(node => node.textContent)"),
    ["主机", "CPU", "内存", "磁盘", "系统", "SSH 状态", "操作"]);
  assert.deepEqual(await evaluate(`({ name: document.querySelector('.host-name-link')?.textContent,
    address: document.querySelector('.host-address')?.textContent,
    expired: document.querySelector('.host-row')?.textContent.includes('数据已过期') })`),
  { name: "测试主机", address: "192.0.2.10", expired: false });
  assert.equal(await evaluate("[...document.querySelectorAll('.host-row a')].some(link => link.textContent === '查看')"), false);
  await checkListLayout({ call, evaluate });
  await retry(() => requestsFor("POST", "/api/v1/collection-requests").length === 1, "initial hosts collection");
  assert.deepEqual(requestsFor("POST", "/api/v1/collection-requests")[0].body, { view: "hosts", limit: 50, due_only: true });
  assert.equal(await evaluate("document.querySelector('.collection-status').hidden"), true);
  const collectionRequests = () => requestsFor("POST", "/api/v1/collection-requests").map(({ body }) => body);
  await nav("services");
  await waitText("main.content", "fixture.service");
  assert.deepEqual(await evaluate("[...document.querySelectorAll('main th')].map(th => th.querySelector('button')?.dataset.sort || th.textContent)"),
    ["name", "target", "state", "cpu", "memory", "操作"]);
  const resourceCells = () => evaluate("[...document.querySelectorAll('main tbody tr')].map(row => [...row.cells].slice(3, 5).map(cell => cell.textContent))");
  assert.deepEqual(await resourceCells(), [["", ""], ["0.0%", "2.0 KiB"]]);
  assert.deepEqual(await evaluate(`(() => {
    const row = [...document.querySelectorAll('tbody tr')].find(row => row.textContent.includes('fixture-deployment'));
    return [...row.querySelectorAll('.service-resource')].map(cell => cell.title);
  })()`), ["未采集到 Kubernetes Metrics API 指标。", "未采集到 Kubernetes Metrics API 指标。"]);
  deployment.desired = 1;
  await nav("targets");
  await nav("services");
  await waitText("main.content", "fixture-deployment");
  assert.equal(await evaluate(`JSON.stringify((() => {
    const row = [...document.querySelectorAll('tbody tr')].find(row => row.textContent.includes('fixture-deployment'));
    const action = [...row.querySelectorAll('button')].find(button => button.textContent.trim() === '启动');
    return { disabled: action.disabled, title: action.title };
  })())`), JSON.stringify({ disabled: true, title: "Deployment 当前副本数不为 0，不能执行启动。" }));
  deployment.desired = 0;
  service.authorized = false;
  await nav("targets");
  await nav("services");
  await waitText("main.content", "fixture.service");
  assert.equal(await evaluate(`JSON.stringify((() => {
    const row = [...document.querySelectorAll('tbody tr')].find(row => row.textContent.includes('fixture.service'));
    const action = [...row.querySelectorAll('button')].find(button => button.textContent.trim() === '停止');
    return { disabled: action.disabled, title: action.title };
  })())`), JSON.stringify({ disabled: true, title: "未配置该服务的启停授权。" }));
  service.authorized = true;
  for (const direction of ["desc", "asc"]) {
    await evaluate("document.querySelector('[data-sort=cpu]').click()");
    await retry(() => evaluate(`document.querySelector('[data-sort=cpu]').parentElement.getAttribute('aria-sort') === '${direction === "desc" ? "descending" : "ascending"}' && !document.querySelector('main').inert`), `sort CPU ${direction}`);
    await retry(async () => (await resourceCells())[0]?.[0] === "0.0%", "missing resources sort last");
    assert.equal(requestsFor("GET", "/api/v1/services").at(-1).query.direction, direction);
  }
  assert.equal(await evaluate("location.hash"), "");
  assert.deepEqual(requestsFor("POST", "/api/v1/session")[0].body, {});
  await retry(() => evaluate("!document.querySelector('#update-dot').hidden"), "update indicator");
  await evaluate("window.smokeDocument = true");
  assert.equal(await evaluate(`(() => {
    const field = document.querySelector('.toolbar select').getBoundingClientRect();
    const action = document.querySelector('.toolbar button').getBoundingClientRect();
    return field.height === action.height && field.bottom === action.bottom;
  })()`), true);
  await setField('select[name="source"]', "cluster", "change");
  await waitText("main.content", "fixture-deployment");
  assert.equal(await evaluate("document.querySelector('main.content').textContent.includes('fixture.service')"), false);
  await evaluate("history.back()");
  await waitText("main.content", "fixture.service");
  await evaluate("history.forward()");
  await waitText("main.content", "fixture-deployment");
  await evaluate("document.querySelector('[data-nav=network]').click(); document.querySelector('[data-nav=targets]').click()");
  await waitText("main.content", host.name);
  assert.equal(await evaluate("document.querySelector('main.content h1').textContent"), "主机管理");
  assert.equal(await evaluate("window.smokeDocument"), true);
  assert.equal(documents, 1);

  const originalObservations = [host, cluster].map((entry) => entry.summary.service_observation);
  serviceCollectionProblem = true;
  host.summary.service_observation = { error_code: "timeout" };
  cluster.summary.service_observation = { error_code: "permission_denied" };
  await nav("services");
  await waitText("main.content", "服务采集超时");
  await waitText("main.content", "当前没有可显示的服务数据");
  await waitText("main.content", "Deployment 的 list 权限");
  host.summary.service_observation = { error_code: "permission_denied" };
  await setField('select[name="source"]', "host", "change");
  await waitText("main.content", "请检查绑定的 SSH 用户是否能通过 systemctl 读取系统服务");
  assert.equal(await evaluate("document.querySelector('main.content').textContent.includes('Deployment 的 list 权限')"), false);
  serviceCollectionProblem = false;
  [host, cluster].forEach((entry, index) => { entry.summary.service_observation = originalObservations[index]; });

  bindingPagination = true;
  const sessionsBefore = requestsFor("POST", "/api/v1/session").length;
  requireSession = true;
  await nav("settings");
  await waitText("main.content", "定时采集");
  assert.equal(requestsFor("POST", "/api/v1/session").length, sessionsBefore + 1);
  assert.deepEqual(await evaluate("[...document.querySelectorAll('main.content button')].map(node => node.textContent)"), ["保存"]);
  const numCollectionBeforeSettingsSave = collectionRequests().length;
  await clickText("main.content button", "保存");
  await waitText("#toast", "已保存采集设置。");
  assert.equal(collectionRequests().length, numCollectionBeforeSettingsSave);
  // Mount the network page, then leave before its collection debounce expires.
  const beforeBriefNetwork = collectionRequests().filter(({ view }) => view === "network").length;
  await nav("network");
  await waitText("main.content", "fixture-if");
  await nav("settings");
  await waitText("main.content", "采集设置");
  await new Promise((resolve) => setTimeout(resolve, 350));
  assert.equal(collectionRequests().filter(({ view }) => view === "network").length, beforeBriefNetwork);
  await nav("targets");
  await clickText("main.content button", "下一页");
  await waitText("main.content", "第二页主机");
  await retry(() => collectionRequests().some(({ cursor }) => cursor === "fixture-binding-next"), "bindings page scope changed");
  assert.deepEqual(collectionRequests().at(-1), { view: "hosts", cursor: "fixture-binding-next", limit: 50, due_only: true });
  await retry(() => requestsFor("GET", "/api/v1/collection-status").some(({ query }) => query.cursor === "fixture-binding-next"), "bindings status follows page cursor");
  bindingPagination = false;

  collectionJobs = true;
  let releaseServiceCollection;
  allowServiceCollection = new Promise((resolve) => { releaseServiceCollection = resolve; });
  await nav("services");
  await waitText("main.content", "fixture.service");
  await setField('select[name="source"]', "host", "change");
  const hostBatches = () => collectionRequests().filter((body) => body.view === "services" && body.source === "host");
  await retry(() => hostBatches().length === 1, "first host service collection request");
  await nav("settings");
  await waitText("main.content", "采集设置");
  await evaluate("history.back()");
  await waitText("main.content", "fixture.service");
  await new Promise((resolve) => setTimeout(resolve, 350));
  assert.deepEqual(hostBatches(), [{ view: "services", source: "host", due_only: true }]);
  releaseServiceCollection();
  allowServiceCollection = null;
  await waitText(".collection-status", "采集0/2");
  assert.equal(await evaluate("document.querySelector('.collection-status').firstElementChild.matches('.collection-spinner')"), true);
  await nav("settings");
  await waitText("main.content", "采集设置");
  const jobReads = () => requests.filter(({ path }) => path.startsWith("/api/v1/jobs/fixture-collection-")).length;
  const readsAtExit = jobReads();
  await new Promise((resolve) => setTimeout(resolve, 850));
  assert.equal(jobReads(), readsAtExit);
  await evaluate("history.back()");
  await waitText(".collection-status", "采集0/2");
  assert.deepEqual(hostBatches(), [{ view: "services", source: "host", due_only: true }]);
  await setField('input[name="q"]', "nonmatching-fixture");
  await clickText("main.content button", "筛选");
  await waitText("main.content", "未找到匹配项");
  assert.deepEqual(hostBatches(), [{ view: "services", source: "host", due_only: true }]);
  collectionJobState = "finished";
  await retry(() => hostBatches().length === 2, "failed and canceled jobs reach terminal and continue batches");
  assert.deepEqual(hostBatches().at(-1), { view: "services", source: "host", cursor: "fixture-next", due_only: true });
  await waitText(".collection-status", "下次采集");
  assert.equal(await evaluate("document.querySelector('.collection-status .collection-spinner') === null"), true);
  assert.equal(requestsFor("GET", "/api/v1/collection-status").some(({ query }) => query.view === "services" && query.cursor), false);
  assert.equal(await evaluate("document.querySelector('#dialog').open"), false);

  let releaseStaleStatus;
  allowNetworkStatus = new Promise((resolve) => { releaseStaleStatus = resolve; });
  const networkStatusBefore = requestsFor("GET", "/api/v1/collection-status").length;
  await nav("network");
  await waitText("main.content", "fixture-if");
  await retry(() => requestsFor("GET", "/api/v1/collection-status").length > networkStatusBefore, "interfaces status in flight");
  assert.equal(await evaluate("new URL(location.href).searchParams.get('id')"), host.id);
  await clickText("main .tabs a", "端口");
  await waitText("main.content", "8080");
  await waitText(".collection-status", "下次采集");
  await retry(() => collectionRequests().some(({ group }) => group === "listeners"), "listeners scope collected");
  assert.match(await evaluate("document.querySelector('.collection-now').textContent"), /^下次采集:1m\d{1,2}s$/);
  releaseStaleStatus();
  allowNetworkStatus = null;
  assert.deepEqual(collectionRequests().filter((body) => body.view === "network").at(-1),
    { view: "network", group: "listeners", target_id: host.id, due_only: true });
  assert.equal(await evaluate("document.querySelector('.collection-status .collection-spinner') === null"), true);
  assert.equal(await evaluate("[...document.querySelectorAll('main button')].some(x => x.textContent === '立即采集')"), false);
  await nav("network");
  await waitText(".collection-status", "采集1/2");
  await nav("settings");
  const statusesAtExit = requestsFor("GET", "/api/v1/collection-status").length;
  await waitText("main.content", "采集设置");
  await new Promise((resolve) => setTimeout(resolve, 1100));
  assert.equal(requestsFor("GET", "/api/v1/collection-status").length, statusesAtExit);
  collectionJobs = false;

  // Reopening a collected page shows its countdown without submitting prematurely.
  await nav("network");
  await clickText("main .tabs a", "路由");
  await waitText("main.content", "192.0.2.0/24");
  await retry(() => routeRound === 1, "first route collection");
  await waitText(".collection-status", "下次采集");
  await nav("settings");
  await waitText("main.content", "采集设置");
  await evaluate("history.back()");
  await waitText(".collection-status", "下次采集");
  assert.equal(routeRound, 1);
  await retry(() => routeRound === 2, "open view recollects at the configured deadline");
  await waitText(".collection-status", "下次采集");
  assert.match(await evaluate("document.querySelector('.collection-now').textContent"), /^下次采集:[0-3]s$/);
  assert.ok(Date.now() < routeDueAt, "the manual action is tested before the next automatic deadline");
  await evaluate("(() => { const action = document.querySelector('.collection-now'); action.click(); action.click(); })()");
  await retry(() => routeRound === 3, "countdown triggers a manual collection");
  await waitText(".collection-status", "下次采集");
  assert.deepEqual(collectionRequests().filter(({ group }) => group === "routes"), [
    ...Array.from({ length: 2 }, () => ({ view: "network", group: "routes", target_id: host.id, due_only: true })),
    { view: "network", group: "routes", target_id: host.id, due_only: false },
  ]);

  await nav("services");
  await clickText("main button", "停止");
  await waitText("#dialog-title", "确认停止服务");
  assert.deepEqual(await confirmState(), { visible: false, checked: false });
  await clickText("#dialog button", "停止");
  await assertUnconfirmed("停止");
  const serviceRequest = { action: "stop", connection_rev: 1, expected_state: "running" };
  const actionRequests = () => requestsFor("POST", `/api/v1/services/${service.id}/actions`).map((request) => request.body);
  assert.deepEqual(actionRequests(), [serviceRequest]);
  await clickConfirmation();
  await clickText("#dialog button", "停止");
  await waitText("#dialog", "成功");
  assert.deepEqual(actionRequests(), [serviceRequest, { ...serviceRequest, confirm_unknown: true }]);
  await clickText("#dialog button", "关闭");

  await clickText("main button", "启动");
  await clickText("#dialog button", "启动");
  await waitText("#dialog", "副本数已写入");
  await waitText("#dialog", "等待副本达到目标");
  await waitText("#dialog", "已达到目标");
  await waitText("#dialog", "实际服务状态运行中");
  assert.equal(convergencePolls, 2);
  assert.deepEqual(requestsFor("POST", `/api/v1/services/${deployment.id}/actions`)[0].body,
    { action: "start", connection_rev: 1, expected_state: "stopped", expected_desired: 0, replicas: 1 });
  await clickText("#dialog button", "关闭");

  await nav("targets");
  await waitText("main.content", host.name);
  await clickText("main button", "绑定主机");
  await setField('#dialog input[name="name"]', "新测试主机");
  await setField('#dialog input[name="ssh_address"]', "192.0.2.10");
  await setField('#dialog input[name="ssh_user"]', "fixture-user");
  await clickText("#dialog button", "选择文件…");
  await retry(() => evaluate("document.querySelector('[name=ssh_key_file]')?.value === '/<FIXTURE_KEY>'"), "selected local path");
  await clickText("#dialog button", "选择文件…");
  await retry(() => pickerCalls === 2, "picker cancel request");
  assert.equal(await evaluate("document.querySelector('[name=ssh_key_file]').value"), "/<FIXTURE_KEY>");
  await clickText("#dialog button", "选择文件…");
  await retry(() => pickerCalls === 3, "third picker request");
  await waitText("#dialog", "正在等待系统文件选择窗口");
  await clickText("#dialog button", "取消选择");
  await retry(() => evaluate("!document.querySelector('#dialog').textContent.includes('正在等待系统文件选择窗口')"), "explicit picker cancellation");
  assert.equal(await evaluate("document.querySelector('[name=ssh_key_file]').value"), "/<FIXTURE_KEY>");
  await clickText("#dialog button", "选择文件…");
  await retry(() => pickerCalls === 4, "picker reopens after cancellation");
  await setField('#dialog input[name="ssh_key_file"]', "~/.ssh/<FIXTURE_MANUAL>");
  await retry(() => evaluate("!document.querySelector('#dialog').textContent.includes('正在等待系统文件选择窗口')"), "manual path cancels picker wait");
  await evaluate("document.querySelector('#dialog details').open = true");
  await setField('#dialog input[name="jump_address"]', "192.0.2.11");
  await setField('#dialog input[name="jump_user"]', "fixture-jump-user");
  await setField('#dialog input[name="jump_key_file"]', "/<FIXTURE_JUMP_KEY>");
  assert.equal(await evaluate("Boolean(document.querySelector('[name=ssh_host_key]'))"), false);
  assert.equal(await evaluate("[...document.querySelectorAll('#dialog button')].some(button => button.textContent === '测试连接')"), false);
  await setField('#dialog input[name="ssh_key_file"]', "/<FIXTURE_KEY>.pub");
  await clickText("#dialog button", "保存绑定");
  await waitText("#dialog", "请确认没有选中 .pub 公钥文件");
  assert.equal(await isButtonDisabled("保存绑定"), false);
  await setField('#dialog input[name="ssh_key_file"]', "~/.ssh/<FIXTURE_MANUAL>");
  await setField('#dialog input[name="ssh_address"]', "192.0.2.99");
  await clickText("#dialog button", "保存绑定");
  await waitText("#dialog", "SSH 主机身份已变化");
  assert.equal(await isButtonDisabled("保存绑定"), false);
  assert.equal(requestsFor("POST", "/api/v1/targets").length, 0);
  await setField('#dialog input[name="ssh_address"]', "192.0.2.10");
  initialHostCollection = true;
  await clickText("#dialog button", "保存绑定");
  await waitText("#dialog", "SHA256:fixture-jump");
  await clickText("#dialog button", "已核对指纹，继续连接");
  await waitText("#dialog", "SHA256:fixture-host");
  await clickText("#dialog button", "已核对指纹，继续连接");
  await waitText("main.content", "新测试主机");
  await waitText(".collection-status", "采集0/1");
  assert.equal(await evaluate("document.querySelector('.page-tools').firstElementChild.matches('.collection-status')"), true);
  const binding = requestsFor("POST", "/api/v1/targets").at(-1);
  assert.deepEqual(requests.slice(requests.indexOf(binding) + 1)
    .filter(({ path, method, body }) => path === "/api/v1/collection-requests" && method === "POST" && body.view === "hosts")
    .map(({ body }) => body), [{ view: "hosts", limit: 50, due_only: true }]);
  assert.equal(binding.body.test_token, "host-ticket");
  hostBindingJobState = "success";
  await retry(() => evaluate("document.querySelector('.collection-status').hidden"), "first host collection completes");
  initialHostCollection = false;
  const hostTests = requestsFor("POST", "/api/v1/targets/test").filter(({ body }) => body.kind === "host");
  assert.deepEqual(hostTests.map(({ body }) => body.ssh_confirmation_token), [undefined, undefined, undefined, "jump-token", "host-token"]);
  assert.equal(hostTests.at(-1).body.ssh.key_file, "~/.ssh/<FIXTURE_MANUAL>");
  assert.equal(hostTests.at(-1).body.ssh.host_key, undefined);
  await clickText("main button", "绑定集群");
  await setField('#dialog input[name="name"]', "新测试集群");
  await clickText("#dialog button", "选择文件…");
  await retry(() => evaluate("document.querySelector('#dialog input[name=kubeconfig]').value === '/<FIXTURE>'"), "selected kubeconfig path");
  await setField('#dialog input[name="context"]', "fixture-context");
  assert.equal(await evaluate("[...document.querySelectorAll('#dialog button')].some(button => button.textContent === '测试连接')"), false);
  await clickText("#dialog button", "保存绑定");
  await waitText("main.content", "新测试集群");
  assert.deepEqual(requestsFor("POST", "/api/v1/targets").at(-1).body,
    { kind: "cluster", name: "新测试集群", kubeconfig: "/<FIXTURE>", context: "fixture-context", test_token: "fixture-ticket" });
  assert.deepEqual(requestsFor("POST", "/api/v1/targets/test").filter(({ body }) => body.kind === "cluster").at(-1).body,
    { kind: "cluster", name: "新测试集群", kubeconfig: "/<FIXTURE>", context: "fixture-context" });

  await clickText("main button", "绑定集群");
  await setField('#dialog input[name="name"]', "插件集群");
  await setField('#dialog input[name="kubeconfig"]', "/<FIXTURE>");
  await setField('#dialog input[name="context"]', "fixture-exec");
  await clickText("#dialog button", "保存绑定");
  await waitText("#dialog", "登录插件配置摘要");
  assert.equal(await evaluate("document.querySelector('#dialog button[type=submit]').disabled"), true);
  assert.deepEqual(requests.find((request) => request.path.endsWith("/kube-exec-approval")).body,
    { kubeconfig: "/<FIXTURE>", context: "fixture-exec" });
  await clickText("#dialog button", "信任插件并重新测试");
  await waitText("main.content", "插件集群");
  assert.deepEqual(requests.filter((request) => request.method === "POST" && request.path === "/api/v1/targets").at(-1).body,
    { kind: "cluster", name: "插件集群", kubeconfig: "/<FIXTURE>", context: "fixture-exec", kube_exec_sha256: execDigest, test_token: "fixture-ticket" });

  await clickText("main tr:first-child .host-action-trigger", "操作");
  assert.deepEqual(await evaluate("[...document.querySelector('[aria-label=集群操作]').querySelectorAll('[role=menuitem]')].map(item => item.textContent.trim())"),
    ["创建告警", "解绑"]);
  assert.equal(await evaluate("[...document.querySelectorAll('main tr:first-child .host-actions > button.action')].some(button => button.textContent.trim() === '编辑')"), true);
  await clickText("main tr:first-child .host-actions > button.action", "编辑");
  await retry(() => evaluate("Boolean(document.querySelector('#dialog input[name=change_connection]'))"), "target edit configuration loaded");
  await evaluate("document.querySelector('#dialog input[name=change_connection]').click()");
  assert.equal(await evaluate("document.querySelector('#dialog input[name=kubeconfig]').value"), "/<FIXTURE>");
  assert.equal(await evaluate("document.querySelector('#dialog input[name=context]').value"), "fixture-context");
  assert.equal(requestsFor("GET", `/api/v1/targets/${cluster.id}`).length, 1);
  await setField('#dialog input[name="context"]', "edit-initial");
  const editRequests = () => requestsFor("PATCH", `/api/v1/targets/${cluster.id}`).map((request) => request.body);
  const firstEdit = { kind: "cluster", name: cluster.name, kubeconfig: "/<FIXTURE>", context: "edit-initial",
    test_token: "ticket-edit-initial", connection_rev: 1 };
  await clickText("#dialog button", "保存修改");
  await assertUnconfirmed("保存修改");
  assert.deepEqual(editRequests(), [firstEdit]);
  await clickConfirmation();
  await setField('#dialog input[name="context"]', "edit-current");
  assert.deepEqual(await confirmState(), { visible: false, checked: false });
  assert.equal(await isButtonDisabled("保存修改"), false);
  const currentEdit = { ...firstEdit, context: "edit-current", test_token: "ticket-edit-current" };
  await clickText("#dialog button", "保存修改");
  await assertUnconfirmed("保存修改");
  assert.deepEqual(editRequests(), [firstEdit, currentEdit]);
  const testsBeforeRename = requestsFor("POST", "/api/v1/targets/test").length;
  await setField('#dialog input[name="name"]', "重命名后的测试集群");
  assert.deepEqual(await confirmState(), { visible: true, checked: false });
  assert.equal(requestsFor("POST", "/api/v1/targets/test").length, testsBeforeRename);
  // Also exercise implicit form submission, which must not bypass the disabled button.
  await evaluate("document.querySelector('#dialog form').requestSubmit()");
  await clickConfirmation();
  await clickText("#dialog button", "保存修改");
  await waitText("#toast", "已保存修改");
  assert.deepEqual(editRequests(), [firstEdit, currentEdit, { ...currentEdit,
    name: "重命名后的测试集群", confirm_unknown: true }]);

  assert.equal(await evaluate("[...document.querySelectorAll('main tr a')].some(link => link.textContent === '查看')"), false);
  await evaluate("document.querySelector('main tr:first-child td:first-child').click()");
  await waitText("main.content", "集群详情");
  await clickText("main a", "主机管理");
  await waitText("main.content", "测试集群");

  await nav("targets");
  await waitText("main.content", host.name);
  await retry(() => evaluate("!document.querySelector('main.content').inert"), "host row is interactive");
  await evaluate(`(() => {
    const cell = document.querySelector('.host-row td:nth-child(2)');
    const range = document.createRange();
    range.selectNodeContents(cell);
    const selection = window.getSelection();
    selection.removeAllRanges();
    selection.addRange(range);
    if (selection.isCollapsed) throw new Error('Fixture must have a text selection');
    cell.click();
  })()`);
  assert.equal(await evaluate("document.querySelector('main.content h1').textContent"), "主机管理");
  await evaluate("window.getSelection().removeAllRanges(); document.querySelector('.host-row td:nth-child(2)').click()");
  await waitText("main.content", "50.0%");
  assert.equal(await evaluate("document.querySelector('main.content h1').textContent"), "主机详情");
  assert.deepEqual(await evaluate(`(() => {
    const title = document.querySelector('.page-title');
    return [...title.children].map(node => node.matches('h1') ? node.textContent
      : node.classList.contains('target-context-control') ? 'target' : node.classList.contains('context-last-success') ? 'last-success' : 'other');
  })()`), ["主机详情", "target", "last-success"]);
  assert.equal(await evaluate("document.querySelector('.context-last-success').textContent.startsWith('最后采集：')"), true);
  assert.deepEqual(await evaluate("[...document.querySelectorAll('[aria-label=CPU趋势] polyline')].map(line => line.getAttribute('points').split(' ').length)"), [2, 2]);
  const metricsTables = await evaluate(`[...document.querySelectorAll('main .metric-inventories table')].map(table => ({
    headers: [...table.querySelectorAll('th')].map(cell => cell.textContent),
    values: [...table.querySelector('tbody td:nth-child(2) > span').children].map(line => line.textContent),
  }))`);
  assert.deepEqual(metricsTables, [
    { headers: ["挂载点", "已用 / 总量", "趋势", "操作"], values: ["50.0%", "2.0 KiB / 4.0 KiB"] },
    { headers: ["接口", "接收 / 发送速率", "接收趋势", "发送趋势"], values: ["接收 1.0 KiB/s", "发送 2.0 KiB/s"] },
  ]);
  const detailLayout = () => evaluate(`(() => {
    const [disk, network] = [...document.querySelectorAll('main .metric-inventories section')].map(el => el.getBoundingClientRect());
    return { beside: disk.right <= network.left && disk.top === network.top, stacked: disk.bottom <= network.top && disk.left === network.left };
  })()`);
  assert.deepEqual(await detailLayout(), { beside: true, stacked: false });
  await checkViewportLists(evaluate, ["磁盘", "网卡"]);
  await call("Emulation.setDeviceMetricsOverride", { width: 365, height: 640, deviceScaleFactor: 1, mobile: true });
  assert.deepEqual(await detailLayout(), { beside: false, stacked: true });
  await checkViewportLists(evaluate, ["磁盘", "网卡"]);
  await call("Emulation.setDeviceMetricsOverride", { width: 1280, height: 900, deviceScaleFactor: 1, mobile: false });
  await clickText("main a", "网络详情");
  await waitText("main.content", "fixture-if");
  assert.deepEqual(await evaluate(`[...document.querySelector('.page-title').children].map(node => node.matches('h1') ? node.textContent
    : node.classList.contains('target-context-control') ? 'target' : node.classList.contains('context-last-success') ? 'last-success' : 'other')`),
  ["网络", "target", "last-success"]);
  await clickText("main .tabs a", "端口");
  await waitText("main.content", "8080");
  await waitText("main.content", "不可读（端口已采集）");
  assert.equal(await evaluate("document.querySelector('main tbody tr')?.cells[2]?.textContent"), "8080");
  await checkViewportLists(evaluate, ["端口"]);
  assert.deepEqual(await evaluate("[...document.querySelectorAll('main th')].map(node => node.textContent)"),
    ["协议", "绑定地址", "端口", "进程"]);
  await clickText("main .tabs a", "防火墙");
  await waitText("main.content", "192.0.2.0/24 → 8080/tcp");
  const firewallRows = await evaluate("[...document.querySelectorAll('main tbody tr')].map(row => [...row.cells].map(cell => cell.textContent))");
  assert.deepEqual(firewallRows, [
    ["ufw", "—", "—", "默认策略", "deny (incoming)"],
    ["ufw", "—", "—", "192.0.2.0/24 → 8080/tcp", "ALLOW IN"],
    ["nftables", "inet / fixture-table", "fixture-input", "默认策略", "drop"],
    ["nftables", "inet / fixture-table", "fixture-input", '{"match":{"left":{"meta":{"key":"l4proto"}},"op":"==","right":"tcp"}}', "accept"],
    ["iptables-legacy · IPV4", "filter", "INPUT", "默认策略", "ACCEPT"],
    ["iptables-legacy · IPV4", "filter", "INPUT", '-s 192.0.2.0/24 -m comment --comment "-j fixture"', "-j DROP"],
    ["iptables-legacy · IPV6", "—", "—", "not_installed", "未检测到工具"],
  ]);

  await waitText("main.content", "防火墙授权：已安装 · v0.1.0 aaaaa · 可用版本 v0.1.0 bbbbb");
  assert.equal(await evaluate("document.querySelector('main').textContent.includes('查看授权设置')"), false);

  await nav("services");
  await waitText("main.content", "fixture.service");
  await evaluate("[...document.querySelectorAll('main tbody tr')].find(row => row.textContent.includes('fixture.service')).querySelector('td:last-child button:last-child').click()");
  await waitText("#dialog", "systemd 服务");
  await clickText("#dialog button", "保存");
  await waitText("main.content", "fixture.service告警");
  assert.deepEqual(rules[0].selector, selector);

  await nav("alerts");
  await clickText("main .tabs a", "未读");
  await clickText("main a", "查看");
  await waitText("main.content", "已投递");
  await checkViewportLists(evaluate, ["投递结果"]);
  await retry(() => event.panel_read_revision === 3, "read marker");
  await retry(() => evaluate("document.querySelector('#unread-count').hidden"), "unread badge updates");
  await clickText("main a", "返回事件列表");
  assert.equal(await evaluate("new URL(location.href).searchParams.get('filter')"), "unread");
  await waitText("main.content", "暂无符合条件的事件");
  showCollectionEvent = true;
  await nav("alerts");
  await waitText("main.content", "采集异常 · 路由");
  await clickText("main tr:first-child a", "查看");
  await waitText("main.content", "采集超时");
  await waitText("main.content", "首次观察");
  await waitText("main.content", "最后观察");
  await waitText("main.content", "回到数据来源");
  assert.equal(await evaluate("document.querySelector('a[href*=routes]').pathname"), "/");
  await nav("alerts");

  await call("Emulation.setDeviceMetricsOverride", { width: 375, height: 760, deviceScaleFactor: 1, mobile: true });
  await clickText("main .tabs a", "通知渠道");
  await waitText("main.content", "发送测试通知");
  await checkViewportLists(evaluate, ["通知渠道"]);
  assert.equal(await evaluate("document.documentElement.scrollWidth <= innerWidth"), true);
  await evaluate("document.querySelector('input[name=panel]').click()");
  await clickText("main button", "保存渠道开关");
  await waitText("main.content", "已保存渠道开关");
  assert.equal(channels.panel, false);
  await clickText("main button", "发送测试通知");
  await waitText("main.content", "已投递");

  assert.equal(await evaluate("document.querySelectorAll('[data-nav]').length"), 5);
  assert.equal(await evaluate("document.querySelector('#version-number').textContent"), release.current);
  await evaluate("document.querySelector('#version-trigger').click()");
  await waitText("#version-popover", release.tag);
  assert.equal(await evaluate("document.querySelector('#version-popover a').href"), release.release_url);
  await waitText("#version-popover", release.release_notes);
  assert.equal(await evaluate("Boolean(document.querySelector('#version-popover em'))"), false);
  await evaluate("document.dispatchEvent(new KeyboardEvent('keydown', { key:'Escape' }))");
  assert.equal(await evaluate("document.querySelector('#version-popover').hidden"), true);
  assert.equal(startupChecks, 1);
  assert.equal(requestsFor("GET", "/api/v1/version/update").length, 1);

  await nav("targets");
  host.firewall_status = "readable";
  host.firewall_authorization_status = "";
  assert.deepEqual(await hostMenu(), ["安装授权", "创建告警", "解绑"]);
  host.firewall_status = "";
  await evaluate("document.querySelector('.host-action-trigger').click()");
  assert.equal(await evaluate("document.querySelectorAll('[data-nav]').length"), 5);
  assert.equal(await evaluate("[...document.querySelectorAll('[data-nav]')].some(item => item.textContent.includes('授权管理'))"), false);
  await hostAction("安装授权");
  await clickText("#dialog button", "安装授权");
  await waitText("#dialog", "自动安装授权需要管理员权限");
  assert.deepEqual(requestsFor("POST", `/api/v1/hosts/${host.id}/firewall-maintenance`).at(-1).body, { action: "install" });
  await clickText("#dialog button", "上传脚本");
  await waitText("#dialog ol li:nth-child(2)", "安装命令");
  assert.deepEqual(requestsFor("POST", `/api/v1/targets/${host.id}/maintenance/upload`).at(-1).body,
    { action: "install", auto_job_id: "firewall-install-fixture" });
  await clickText("#dialog button", "重新检测授权");
  await clickText("#dialog button", "重新检测授权");
  await waitText("#dialog", "v1.1.0 bbbbb");
  assert.deepEqual(await hostMenu(), ["卸载授权", "创建告警", "解绑"]);
  await hostAction("卸载授权");
  await clickText("#dialog button", "卸载授权");
  await waitText("#dialog", "自动卸载授权需要管理员权限");
  await clickText("#dialog button", "使用管理员凭据");
  await setField('#dialog input[name="admin_user"]', "fixture-admin");
  await setField('#dialog input[name="admin_key_file"]', "/<FIXTURE_ADMIN_KEY>");
  await clickText("#dialog button", "卸载授权");
  await waitText("#dialog", "未安装");

  host.firewall_authorization_status = "native";
  await nav("services");
  await waitText("main.content", "fixture.service");
  await nav("targets");
  await waitText("main.content", host.name);
  assert.deepEqual(await hostMenu(), ["创建告警", "解绑"]);

  firewallUninstalled = false;
  firewallVersion = oldFirewallVersion;
  await hostAction("解绑");
  await waitText("#dialog-title", "确认解绑");
  assert.deepEqual(await confirmState(), { visible: false, checked: false });
  await clickText("#dialog button", "确认解绑");
  await assertUnconfirmed("确认解绑");
  const unbindRequests = () => requestsFor("DELETE", `/api/v1/targets/${host.id}`).map((request) => request.query);
  assert.deepEqual(unbindRequests(), [{}]);
  const uploads = () => requestsFor("POST", `/api/v1/targets/${host.id}/maintenance/upload`)
    .map(({ body }) => body).filter((body) => body.action === "uninstall");
  await clickConfirmation();
  firewallReachable = false;
  await clickText("#dialog button", "确认解绑");
  await waitText("#dialog", "请检查 SSH 连接后重试");
  assert.equal(targets.includes(host), true);
  await clickText("#dialog button", "关闭");
  firewallReachable = true;
  await hostAction("解绑");
  await clickText("#dialog button", "确认解绑");
  await assertUnconfirmed("确认解绑");
  await clickConfirmation();
  await clickText("#dialog button", "确认解绑");
  await waitText("#dialog", "是否上传维护脚本");
  assert.equal(targets.includes(host), true);
  assert.deepEqual(uploads(), []);
  await clickText("#dialog button", "上传脚本");
  await waitText("#dialog", "等待管理员");
  await waitText("#dialog ol li:first-child", "先单独运行 /bin/sh 并按回车");
  await waitText("#dialog .command", "sudo -- /bin/sh");
  assert.deepEqual(uploads().at(-1), { action: "uninstall", auto_job_id: "firewall-uninstall-fixture" });
  await clickText("#dialog button", "重新检测授权");
  await clickText("#dialog button", "重新检测授权");
  await waitText("#dialog", "尚未确认清理，主机绑定仍保留。");
  assert.equal(targets.includes(host), true);
  assert.equal(unbindRequests().length, 4);
  uninstallCommandApplied = true;
  await clickText("#dialog button", "重新检测授权");
  await evaluate("document.querySelector('#dialog input[name=auto]').click()");
  await setField('#dialog input[name="admin_user"]', "fixture-admin");
  await setField('#dialog input[name="admin_key_file"]', "/<FIXTURE_ADMIN_KEY>");
  await clickText("#dialog button", "重新检测授权");
  await retry(() => evaluate(`(() => {
    const rows = [...document.querySelectorAll('main.content .host-row')];
    return rows.length === 1 && rows[0].textContent.includes('新测试主机');
  })()`), "only the newly bound host remains");
  assert.deepEqual(unbindRequests(), [{}, { confirm_unknown: "true" }, {}, ...Array.from({ length: 2 }, () => ({ confirm_unknown: "true" }))]);

  await call("Page.reload");
  await retry(() => evaluate("!document.querySelector('#update-dot').hidden"), "update still available in reloaded tab");
  assert.equal(startupChecks, 1);
  await evaluate("document.querySelector('#version-trigger').click()");
  await clickText("#version-popover button", "更新");
  await waitText("#version-number", release.tag);
  await retry(() => startupChecks === 2, "one check after application restart");
  assert.equal(await evaluate("document.querySelector('#update-dot').hidden"), true);
  assert.deepEqual(requestsFor("POST", "/api/v1/version/update/apply").map(({ body }) => body),
    [{ tag: release.tag, sha256: release.sha256 }]);

  // Exercise the real frontend with a transport-only native fixture. No business
  // API should reach the HTTP fixture when the document-start bridge is present.
  const desktopHost = { ...host, id: "desktop-host-fixture", name: "桌面测试主机" };
  const desktopSessionCount = requestsFor("POST", "/api/v1/session").length;
  const desktopHTTPCount = requests.length;
  await call("Page.addScriptToEvaluateOnNewDocument", {
    source: `
      window.desktopRequests = [];
      Object.defineProperty(window, "imonDesktop", { value: Object.freeze({
        request: async (request) => {
          desktopRequests.push(request);
          const result = (body, status = 200) => ({ request_id: request.request_id, status, body });
          const path = new URL(request.path, location.href).pathname;
          switch (path) {
            case "/api/v1/targets": return result(${JSON.stringify(list([desktopHost]))});
            case "/api/v1/services": return result(${JSON.stringify(list([service]))});
            case "/api/v1/alert-events": return result({ items: [], unread_count: 0 });
            case "/api/v1/version": return result({ current: "0.1.0" });
            case "/api/v1/version/update": return result({ state: "unconfigured" });
            case "/api/v1/collection-requests": return result({ jobs: [] });
            case "/api/v1/collection-status": return result({ server_now: Date.now(), next_run_at: null, active: null });
            default: return result({ message: "Unexpected bridge route" }, 404);
          }
        },
        choosePrivateKey: async () => ({ path: "/<FIXTURE_DESKTOP_KEY>", canceled: false }),
      }) });
    `,
  });
  await call("Page.navigate", { url: url + "/?desktop-fixture=1#?view=services" });
  try {
    await waitText("main.content", "fixture.service");
  } catch (failure) {
    throw new Error(JSON.stringify(await evaluate("({ body:document.body.innerText, href:location.href, calls:window.desktopRequests })")), { cause: failure });
  }
  await nav("targets");
  await waitText("main.content", desktopHost.name);
  assert.equal(await evaluate("location.hash"), "#?view=targets");
  assert.equal(await evaluate("location.search"), "?desktop-fixture=1");
  await clickText("main button", "绑定主机");
  await clickText("#dialog button", "选择文件…");
  await retry(() => evaluate("document.querySelector('[name=ssh_key_file]').value === '/<FIXTURE_DESKTOP_KEY>'"), "desktop picker");
  await clickText("#dialog button", "取消");
  await evaluate("history.back()");
  await waitText("main.content", "fixture.service");
  assert.equal(await evaluate("location.hash"), "#?view=services");
  assert.equal(await evaluate("desktopRequests.some(request => request.path === '/api/v1/session')"), false);
  assert.equal(requestsFor("POST", "/api/v1/session").length, desktopSessionCount);
  assert.equal(requests.length, desktopHTTPCount);
  assert.deepEqual(browserErrors, []);
  console.log("Web smoke passed: stable sessions, desktop bridge routing, scoped collection and progress, aligned controls, SSH picker, service/target/alert workflows, firewall maintenance, mobile layout, startup check and update restart");
} finally {
  socket?.close();
  browser.kill();
  await browserExit.catch(() => {});
  server.close();
  await rm(profile, { recursive: true, force: true, maxRetries: 3 });
}

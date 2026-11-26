import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { once } from "node:events";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createServer as createTLS } from "node:https";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";

const binary = process.argv[2];
const chrome = process.env.CHROME_BIN;
if (!binary || !chrome) {
  throw new Error("Usage: CHROME_BIN=<Executable> node web/real-collection-smoke.mjs <Web binary>");
}

const loopback = "127.0.0.1";
const interval = 10;
const deployments = [];
const temp = await mkdtemp(join(tmpdir(), "imon-real-"));
let upstream, panel, browser, socket, heldDeployment;

async function listen(server) {
  server.listen(0, loopback);
  await once(server, "listening");
  return server.address().port;
}

async function retry(read, label, timeout = 8000) {
  const deadline = performance.now() + timeout;
  let failure;
  do {
    try {
      const value = await read();
      if (value) return value;
    } catch (error) {
      failure = error;
    }
    await delay(50);
  } while (performance.now() < deadline);
  throw new Error(`Timed out: ${label}`, { cause: failure });
}

function run(program, args) {
  const process = spawn(program, args, { stdio: ["ignore", "ignore", "pipe"] });
  let diagnostics = "";
  process.stderr.on("data", (chunk) => { diagnostics += chunk; });
  process.on("error", (error) => { diagnostics += error.message; });
  return {
    process,
    check() {
      if (!process.pid || process.exitCode !== null) throw new Error(diagnostics || `Process exited: ${program}`);
    },
  };
}

async function stop(child) {
  if (!child?.process.pid || child.process.exitCode !== null) return;
  const process = child.process;
  const exited = once(process, "exit");
  process.kill();
  const timeout = setTimeout(() => process.kill("SIGKILL"), 3000);
  try {
    await exited;
  } finally {
    clearTimeout(timeout);
  }
}

try {
  const secret = join(temp, "fixture-key.pem");
  const certificate = join(temp, "fixture-cert.pem");
  execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
    "-subj", "/CN=localhost", "-addext", `subjectAltName=IP:${loopback}`,
    "-keyout", secret, "-out", certificate], { stdio: "ignore" });
  const cert = await readFile(certificate);
  upstream = createTLS({ cert, key: await readFile(secret) }, (request, response) => {
    let body, gate;
    const path = new URL(request.url, `https://${loopback}`).pathname;
    if (request.method === "GET") {
      if (path === "/api/v1/namespaces/kube-system") {
        body = { metadata: { name: "kube-system", uid: "fixture-cluster" } };
      } else if (path === "/apis/apps/v1/deployments") {
        deployments.push(Date.now());
        if (heldDeployment && !heldDeployment.used) {
          heldDeployment.used = true;
          gate = heldDeployment.promise;
        }
        body = { items: [{
          metadata: { name: "fixture-workload", namespace: "default", uid: "fixture-deployment", generation: 1 },
          spec: { replicas: 1 },
          status: { observedGeneration: 1, replicas: 1, readyReplicas: 1 },
        }] };
      } else if (["/api/v1/nodes", "/api/v1/namespaces", "/api/v1/pods", "/api/v1/services",
        "/apis/discovery.k8s.io/v1/endpointslices"].includes(path)) {
        body = { items: [] };
      }
    }
    const send = () => {
      response.writeHead(body ? 200 : 404, { "Content-Type": "application/json" });
      response.end(JSON.stringify(body ?? {}));
    };
    if (gate) gate.then(send);
    else send();
  });
  const upstreamPort = await listen(upstream);
  const kubeconfig = join(temp, "fixture.json");
  await writeFile(kubeconfig, JSON.stringify({
    apiVersion: "v1", kind: "Config", "current-context": "fixture",
    contexts: [{ name: "fixture", context: { cluster: "fixture" } }],
    clusters: [{ name: "fixture", cluster: {
      server: `https://${loopback}:${upstreamPort}`, "certificate-authority-data": cert.toString("base64"),
    } }],
  }), { mode: 0o600 });

  const reservation = createServer();
  const port = await listen(reservation);
  await new Promise((finish) => reservation.close(finish));
  const origin = `http://${loopback}:${port}`;
  panel = run(resolve(binary), ["--port", String(port), "--data-dir", join(temp, "data"), "--release-repo", ""]);
  await retry(async () => {
    panel.check();
    return (await fetch(origin)).ok;
  }, "real panel startup", 12000);

  let cookie;
  async function api(method, path, status, body) {
    const response = await fetch(origin + "/api/v1" + path, {
      method,
      headers: {
        Origin: origin,
        ...(cookie && { Cookie: cookie }),
        ...(body && { "Content-Type": "application/json" }),
      },
      body: body && JSON.stringify(body),
    });
    const payload = await response.text();
    assert.equal(response.status, status, `${method} ${path}: ${payload}`);
    if (path === "/session") cookie = response.headers.get("set-cookie")?.split(";")[0];
    return payload ? JSON.parse(payload) : null;
  }
  await api("POST", "/session", 204, {});
  await api("PUT", "/sampling-settings", 200, {
    poll_enabled: true, host_interval: 60, network_interval: 300, cluster_interval: interval, timeout: 20,
  });
  const config = { kind: "cluster", name: "fixture", kubeconfig, context: "fixture" };
  const proof = await api("POST", "/targets/test", 200, config);
  const target = await api("POST", "/targets", 201, { ...config, test_token: proof.test_token });
  const before = deployments.length;

  const profile = join(temp, "chrome");
  browser = run(chrome, ["--headless=new", "--disable-gpu", "--disable-background-networking",
    "--no-first-run", "--remote-debugging-port=0", `--user-data-dir=${profile}`, "about:blank"]);
  const protocolURL = await retry(async () => {
    browser.check();
    const [port] = (await readFile(join(profile, "DevToolsActivePort"), "utf8")).split("\n");
    const tabs = await (await fetch(`http://${loopback}:${port}/json/list`)).json();
    return tabs.find((tab) => tab.type === "page")?.webSocketDebuggerUrl;
  }, "browser startup", 15000);
  socket = new WebSocket(protocolURL);
  await once(socket, "open");
  let commandID = 0;
  const commands = new Map();
  const posts = [];
  socket.addEventListener("message", ({ data }) => {
    const message = JSON.parse(data);
    if (message.method === "Network.requestWillBeSent") {
      const { url, method, postData } = message.params.request;
      if (url === origin + "/api/v1/collection-requests" && method === "POST") {
        posts.push({ at: message.params.wallTime * 1000, body: JSON.parse(postData) });
      }
    }
    commands.get(message.id)?.(message);
  });
  const call = (method, params = {}) => new Promise((finish, reject) => {
    const id = ++commandID;
    const timeout = setTimeout(() => {
      commands.delete(id);
      reject(new Error(`CDP timed out: ${method}`));
    }, 5000);
    commands.set(id, ({ result, error }) => {
      commands.delete(id);
      clearTimeout(timeout);
      if (error) reject(new Error(error.message));
      else finish(result);
    });
    socket.send(JSON.stringify({ id, method, params }));
  });
  await call("Page.enable");
  await call("Network.enable", { maxPostDataSize: 4096 });
  const evaluate = async (expression) => {
    const response = await call("Runtime.evaluate", { expression, returnByValue: true });
    if (response.exceptionDetails) throw new Error(response.exceptionDetails.text);
    return response.result.value;
  };
  const click = (nav) => evaluate(`document.querySelector('[data-nav="${nav}"]').click()`);
  const workload = () => evaluate("document.querySelector('tbody')?.textContent.includes('fixture-workload')");
  const countdown = () => evaluate(`(() => {
    const element = document.querySelector(".page-tools .collection-status:not([hidden])");
    const action = element?.querySelector(".collection-now:not(:disabled)");
    const match = /^下次采集:(?:([1-9]\\d*)m)?(\\d{1,2})s$/.exec(action?.textContent);
    return action?.getBoundingClientRect().width > 0 && match ? Number(match[1] || 0) * 60 + Number(match[2]) : null;
  })()`);
  const filteredProgress = () => evaluate(`(() => {
    const query = new URLSearchParams(location.search);
    const slot = document.querySelector(".page-tools .collection-status:not([hidden])");
    return query.get("target") === ${JSON.stringify(target.id)} &&
      !document.querySelector('[aria-busy="true"]') &&
      slot?.getBoundingClientRect().width > 0 && slot.textContent === "采集0/1" &&
      Boolean(slot.querySelector(".collection-spinner"));
  })()`);

  await call("Page.navigate", { url: origin + "/?view=services" });
  await retry(workload, "first collected deployment visible");
  assert.equal(deployments.length - before, 1, "first entry should collect exactly once");
  assert.equal(posts.length, 1);
  assert.equal(posts[0].body.view, "services");
  const { next_foreground_at: due } = await api("GET", "/collection-status?view=services", 200);

  await click("settings");
  await retry(() => evaluate("location.search.includes('view=settings') && Boolean(document.querySelector('[name=cluster_interval]'))"), "settings route");
  await click("services");
  await retry(workload, "existing snapshot after returning");
  if (!due) {
    // Capture both symptoms when running against the old package.
    await delay(1500);
    assert.fail(`No next deadline after first collection; re-entry: ${posts.length} POST(s), ${deployments.length - before} upstream collection(s), countdown ${JSON.stringify(await countdown())}`);
  }
  assert.ok(due > Date.now(), "configured interval should start from the completed collection");
  assert.equal(posts[0].body.due_only, true);
  const returned = await retry(countdown, "countdown on re-entry");
  await retry(async () => {
    if (Date.now() >= due) throw new Error("interval elapsed before observing countdown change");
    const text = await countdown();
    return text && text < returned;
  }, "decreasing visible countdown before deadline", 3500);
  assert.ok(Date.now() < due);
  assert.equal(posts.length, 1, "returning before the deadline should not submit a collection");
  assert.equal(deployments.length - before, 1, "returning before the deadline should not reach Kubernetes");
  console.log("Before deadline: one service POST, one upstream collection, visible decreasing countdown after re-entry.");

  heldDeployment = Promise.withResolvers();
  await retry(() => heldDeployment.used, "automatic collection after configured interval", (interval + 6) * 1000);
  assert.equal(deployments.length - before, 2);
  assert.equal(posts.length, 2);
  assert.ok(posts[1].at >= due - 20, "second request began before the configured deadline");
  assert.ok(deployments[before + 1] >= due, "Kubernetes was collected before the configured deadline");

  await evaluate(`(() => {
    const field = document.querySelector('select[name="target"]');
    field.value = ${JSON.stringify(target.id)};
    field.dispatchEvent(new Event("change", { bubbles: true }));
  })()`);
  await retry(filteredProgress, "progress follows the in-flight task into an overlapping service filter");
  await delay(1250);
  assert.ok(await filteredProgress(), "the filtered page should still display the held task");
  assert.equal(posts.length, 2, "the overlapping filter should not submit another collection");
  assert.equal(deployments.length - before, 2, "the overlapping filter should not reach Kubernetes again");
  console.log("Collection in progress: overlapping cluster filter shows 采集0/1 without an extra POST or upstream request.");

  heldDeployment.resolve();
  await retry(countdown, "next interval visible after automatic refresh");
  console.log("After deadline: one new service POST, one new upstream collection, countdown restarted.");

  const { next_foreground_at: next } = await api("GET", `/collection-status?view=services&target_id=${encodeURIComponent(target.id)}`, 200);
  assert.ok(Date.now() < next);
  await evaluate("(() => { const control = document.querySelector('.collection-now'); control.click(); control.click(); })()");
  await retry(() => deployments.length - before === 3, "countdown triggers immediate collection");
  await retry(countdown, "next interval visible after manual refresh");
  assert.equal(posts.length, 3, "rapid activation should only submit one request");
  assert.deepEqual(posts[2].body, { view: "services", target_id: target.id, due_only: false });
  assert.ok(deployments[before + 2] < next, "manual collection should not wait for the configured deadline");
  console.log("Countdown activated twice: one immediate service POST and one upstream collection, countdown restarted.");
} finally {
  heldDeployment?.resolve();
  socket?.close();
  await Promise.all([stop(browser), stop(panel)]);
  if (upstream) await new Promise((finish) => upstream.close(finish));
  await rm(temp, { recursive: true, force: true });
}

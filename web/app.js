"use strict";

const session = document.querySelector("#session");
const sessionStatus = document.querySelector("#session-status");
const sessionRetry = document.querySelector("#session-retry");
const workspace = document.querySelector("#workspace");
const content = document.querySelector("#content");
const routeProgress = document.querySelector("#route-progress");
const dialog = document.querySelector("#dialog");
const dialogBody = document.querySelector("#dialog-body");
const badge = document.querySelector("#unread-count");
const toast = document.querySelector("#toast");
const versionTrigger = document.querySelector("#version-trigger");
const versionNumber = document.querySelector("#version-number");
const versionPopover = document.querySelector("#version-popover");
const updateDot = document.querySelector("#update-dot");
const statusText = {
  running: "运行中", failed: "失败", stopped: "停止", starting: "启动中",
  pending: "等待采集", stale: "数据已过期", success: "成功", partial: "部分成功",
  queued: "排队", running_job: "执行中", canceled: "取消", interrupted: "中断",
  unknown: "待核实", awaiting_admin: "等待管理员", unreachable: "连接失败",
  unreadable: "不可读", unsupported: "不支持", inactive: "未启用", disabled: "未启用",
  not_found: "未检测到工具", not_detected: "未检测到工具", not_installed: "未检测到工具",
  readable: "可读", no_rules: "无规则", active: "活动", recovered: "已恢复",
  monitoring_stopped: "监控停止", configuration_changed: "配置变更",
};
const severityText = { info: "信息", warning: "警告", critical: "严重" };
const channelText = { panel: "面板通知", telegram: "Telegram", email: "邮箱" };
const convergenceText = { pending: "等待副本达到目标", confirmed: "已达到目标", workload_failed: "工作负载失败", not_confirmed: "未确认达到目标" };
const networkTabs = { interfaces: "接口", routes: "路由", listeners: "端口", firewall: "防火墙" };
const clusterTabs = { namespaces: "命名空间", deployments: "部署", pods: "Pod", services: "服务", nodes: "节点" };
const serviceStates = ["running", "failed", "stopped", "starting"];
const desktop = window.imonDesktop;
const get = (path, options) => api(path, "GET", undefined, options);
const targetPath = (id) => `/targets/${key(id)}`;
const key = (value) => encodeURIComponent(String(value));
let generation = 0;
let routeRead;
let readRequest = 0;
let toastTimer;
let localVersion;
let updateInfo;
let updateRunning = false;
let versionFeedback = "";
let versionFailed = false;
let sessionOpening;
let webSessionRevision = 0;
let nextRequestID = 0;
let cancelWebFilePicker;

class APIError extends Error {
  constructor(response, data) {
    super(data?.message || `请求失败（${response.status}）`);
    this.status = response.status;
    this.code = data?.code;
    this.details = data?.details;
  }
}

function openWebSession() {
  sessionOpening ||= fetch("/api/v1/session", {
    method: "POST", credentials: "same-origin", cache: "no-store",
    headers: { "Content-Type": "application/json" }, body: "{}",
  }).then(async (response) => {
    if (!response.ok) throw new APIError(response, await response.json().catch(() => null));
    webSessionRevision += 1;
  }).finally(() => { sessionOpening = null; });
  return sessionOpening;
}

async function api(path, method, body, options = {}) {
  if (desktop) {
    const request_id = String(++nextRequestID);
    const response = await desktop.request({ request_id, method, path: "/api/v1" + path, ...(body === undefined ? {} : { body }) });
    if (!response || response.request_id !== request_id || !Number.isInteger(response.status)) throw new Error("本地应用返回了无效响应。");
    if (response.status < 200 || response.status >= 300) throw new APIError(response, response.body);
    return response.body;
  }
  const request = { method, credentials: "same-origin", cache: "no-store" };
  if (body !== undefined) {
    request.headers = { "Content-Type": "application/json" };
    request.body = JSON.stringify(body);
  }
  if (options.signal) request.signal = options.signal;
  const sessionRevision = webSessionRevision;
  let response = await fetch("/api/v1" + path, request);
  if (response.status === 401 && !options.signal?.aborted) {
    try {
      if (sessionRevision === webSessionRevision) await openWebSession();
      response = await fetch("/api/v1" + path, request);
    } catch (error) {
      if (options.signal?.aborted) throw error;
    }
  }
  const data = response.status === 204 ? null : await response.json().catch(() => null);
  if (!response.ok) {
    if (response.status === 401 && path !== "/session" && !options.keepSession && !options.signal?.aborted && !updateRunning) {
      generation += 1;
      routeRead?.abort();
      clearCollections();
      if (dialog.open) dialog.close();
      closeVersion();
      workspace.hidden = true;
      session.hidden = false;
      sessionStatus.textContent = "本地会话未建立。";
      sessionRetry.hidden = false;
    }
    throw new APIError(response, data);
  }
  return data;
}

function element(tag, attributes = {}, ...children) {
  const node = document.createElement(tag);
  for (const [attribute, value] of Object.entries(attributes)) {
    if (value === undefined || value === null || value === false) continue;
    if (attribute === "class") node.className = value;
    else if (attribute.startsWith("on")) node.addEventListener(attribute.slice(2), value);
    else if (value === true) node.setAttribute(attribute, "");
    else node.setAttribute(attribute, String(value));
  }
  node.append(...children.flat(Infinity).filter((child) => child !== null && child !== undefined && child !== false));
  return node;
}

function params(values) {
  const query = new URLSearchParams();
  for (const [field, value] of Object.entries(values)) {
    if (value !== "" && value !== undefined && value !== null && value !== false) {
      query.set(field, typeof value === "object" ? JSON.stringify(value) : value);
    }
  }
  const encoded = query.toString();
  return encoded ? "?" + encoded : "";
}

function locationFor(view, values = {}) {
  return (desktop ? "#" : "/") + params({ view, ...values });
}

function link(label, href, kind = "") {
  return element("a", { href, class: kind && `action ${kind}` }, label);
}

function button(label, onclick, kind = "secondary", attributes = {}) {
  return element("button", { type: "button", class: `action ${kind}`, onclick, ...attributes }, label);
}

function submit(label = "保存") {
  return element("button", { type: "submit", class: "action primary" }, label);
}

function control(label, input, wide = false) {
  const wrapper = element("label", { class: `control${wide ? " wide" : ""}` }, label, input);
  return wrapper;
}

function localFileField(label, field, wide = false) {
  let edits = 0;
  let pending;
  const feedback = notice("");
  field.addEventListener("input", () => {
    edits += 1;
    pending?.();
    formError(feedback, null);
  });
  const choose = button("选择文件…", async () => {
    if (pending) {
      pending();
      formError(feedback, null);
      return;
    }
    if (cancelWebFilePicker) {
      formError(feedback, "另一个文件选择窗口仍在打开。");
      return;
    }
    const revision = edits;
    const controller = desktop ? null : new AbortController();
    const cancel = () => controller.abort();
    if (controller) cancelWebFilePicker = pending = cancel;
    const active = () => field.isConnected && dialog.open && !field.disabled && revision === edits && !controller?.signal.aborted;
    if (desktop) choose.disabled = true;
    else choose.textContent = "取消选择";
    formError(feedback, null);
    feedback.textContent = "正在等待系统文件选择窗口…";
    try {
      const result = desktop ? await desktop.choosePrivateKey()
        : await api("/local/file-picker", "POST", undefined, { signal: controller.signal });
      if (!active()) return;
      formError(feedback, null);
      if (result?.path) {
        field.value = result.path;
        field.dispatchEvent(new Event("input", { bubbles: true }));
      }
    } catch (error) {
      if (active()) formError(feedback, error);
    } finally {
      if (cancelWebFilePicker === cancel) cancelWebFilePicker = undefined;
      pending = undefined;
      choose.textContent = "选择文件…";
      choose.disabled = field.disabled;
    }
  });
  return element("div", { class: `file-field${wide ? " wide" : ""}` },
    element("div", { class: "file-input" }, control(label, field), choose), feedback);
}

function privateKeyField(label, field, wide = false) {
  return localFileField(label, field, wide);
}

function input(name, value, extra = {}) {
  return element("input", { name, value: value ?? "", ...extra });
}

function select(name, entries, value) {
  const node = element("select", { name }, entries.map(([id, label]) => element("option", { value: id }, label)));
  if ([...node.options].some((option) => option.value === String(value))) node.value = String(value);
  return node;
}

function checkbox(name, checked) {
  return element("input", { name, type: "checkbox", checked });
}

function notice(message, error = false) {
  return element("p", { class: error ? "notice error" : "notice", role: "status" }, message);
}

function formError(box, error) {
  box.textContent = error instanceof Error ? error.message : String(error ?? "");
  box.classList.toggle("error", Boolean(error));
}

function formatTime(value) {
  if (!value) return "—";
  const time = new Date(value);
  return Number.isFinite(time.getTime()) ? time.toLocaleString() : "—";
}

function formatPercent(value) {
  return Number.isFinite(value) ? `${value.toFixed(1)}%` : "—";
}

function formatBytes(value, perSecond = false) {
  if (!Number.isFinite(value)) return "—";
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let index = 0;
  while (value >= 1024 && index < units.length - 1) {
    value /= 1024;
    index += 1;
  }
  return `${value.toFixed(index === 0 ? 0 : 1)} ${units[index]}${perSecond ? "/s" : ""}`;
}

function usageCell(usage, cores = false) {
  const used = cores ? usage?.used_cores : usage?.used_bytes;
  const total = cores ? usage?.total_cores : usage?.total_bytes;
  if (![used, total, usage?.percent].every(Number.isFinite)) return "—";
  const units = cores ? ["核"] : ["B", "KiB", "MiB", "GiB", "TiB"];
  let index = 0;
  while (index < units.length - 1 && total >= 1024 ** (index + 1)) index++;
  const divisor = 1024 ** index;
  const format = (value) => `${(value / divisor).toFixed(cores || index > 0 ? 1 : 0)} ${units[index]}`;
  return element("span", { class: "resource-usage", title: usage.mountpoint },
    element("span", { class: "resource-percent" }, formatPercent(usage.percent)),
    element("span", { class: "resource-capacity" }, `${format(used)} / ${format(total)}`));
}

function display(value) {
  if (value === undefined || value === null || value === "") return "—";
  if (Array.isArray(value)) return value.length ? value.map(display).join("、") : "—";
  if (typeof value === "object") return JSON.stringify(value);
  if (typeof value === "boolean") return value ? "是" : "否";
  return String(value);
}

function chip(value, label = statusText[value] || display(value)) {
  const style = ["running", "success", "recovered"].includes(value) ? "ok"
    : ["failed", "unreachable", "unreadable"].includes(value) ? "bad"
    : ["starting", "stale", "partial", "active", "unknown", "awaiting_admin"].includes(value) ? "wait" : "";
  return element("span", { class: `chip ${style}` }, label);
}

function meta(value) {
  return element("span", { class: "meta" }, value);
}

function tableRow(cells, attributes = {}) {
  return element("tr", attributes, cells.map((cell) => element("td", {}, cell instanceof Node ? cell : display(cell))));
}

function listTable(label, columns, rows, empty = "暂无数据") {
  const head = element("tr", {}, columns.map((column) => column instanceof Node ? column : element("th", { scope: "col" }, column)));
  const entries = rows.map((row) => row instanceof Node ? row : tableRow(row));
  if (!entries.length) entries.push(element("tr", {}, element("td", { class: "empty", colspan: columns.length }, empty)));
  return element("div", { class: "inventory", tabindex: 0, role: "region", "aria-label": label },
    element("table", { "aria-label": label }, element("thead", {}, head), element("tbody", {}, entries)));
}

function heading(title, actions = [], collecting = false, context = null) {
  const name = element("h1", {}, title);
  const titleLine = context
    ? element("div", { class: "page-title-heading" }, name,
      element("span", { class: "page-title-separator", "aria-hidden": "true" }, "/"), context.picker.control)
    : name;
  return element("header", { class: "page-head" },
    element("div", { class: context ? "page-title page-title-with-target" : "page-title" }, titleLine, context?.lastSuccess),
    element("div", { class: "page-tools" },
      collecting ? element("div", { class: "collection-status", hidden: true }) : null,
      actions.length ? element("div", { class: "actions" }, actions) : null));
}

function tabs(entries, active) {
  return element("nav", { class: "tabs", "aria-label": "栏目" }, entries.map(([id, label, href]) =>
    element("a", { class: "tab", href, "aria-current": id === active ? "page" : undefined }, label)));
}

function pairs(entries) {
  return element("dl", { class: "key-value" }, entries.map(([label, value]) => [
    element("dt", {}, label), element("dd", {}, value instanceof Node ? value : display(value)),
  ]));
}

function notify(message) {
  clearTimeout(toastTimer);
  toast.textContent = message;
  toast.hidden = false;
  toastTimer = setTimeout(() => { toast.hidden = true; }, 4500);
}

function showDialog(title, body) {
  closeVersion();
  cancelWebFilePicker?.();
  dialogBody.replaceChildren(element("div", { class: "stack" },
    element("h2", { id: "dialog-title" }, title), body));
  if (!dialog.open) dialog.showModal();
}

function closeDialog() {
  cancelWebFilePicker?.();
  dialog.close();
  dialogBody.replaceChildren();
}

dialog.addEventListener("close", () => {
  if (!dialog.open) {
    cancelWebFilePicker?.();
    dialogBody.replaceChildren();
  }
});

function actionForm(title, description, label, action, kind = "primary", confirmUnknown = "") {
  const error = notice("");
  const acknowledged = checkbox("confirm_unknown", false);
  const confirmation = element("label", { class: "checks", hidden: true }, acknowledged, confirmUnknown);
  const awaitingConfirmation = () => !confirmation.hidden && !acknowledged.checked;
  const confirm = button(label, async () => {
    confirm.disabled = true;
    formError(error, null);
    try {
      await action(acknowledged.checked);
    } catch (failure) {
      formError(error, failure);
      if (confirmUnknown && failure.code === "result_unconfirmed") {
        confirmation.hidden = false;
        acknowledged.checked = false;
      }
    } finally {
      confirm.disabled = awaitingConfirmation();
    }
  }, kind);
  acknowledged.addEventListener("change", () => { confirm.disabled = awaitingConfirmation(); });
  showDialog(title, element("div", { class: "stack" }, description, error, confirmUnknown ? confirmation : null,
    element("div", { class: "form-actions" }, button("取消", closeDialog), confirm)));
}

function readCapture() {
  readRequest += 1;
  return readRequest;
}

function setUnread(count, request = readCapture()) {
  if (request !== readRequest || !Number.isInteger(count)) return;
  badge.textContent = String(count);
  badge.hidden = count < 1;
}

async function refreshUnread() {
  const request = readCapture();
  try {
    setUnread((await get("/alert-events?limit=1"))?.unread_count, request);
  } catch {
    // Unread count can be refreshed independently from the active page.
  }
}

const views = {
  services: { title: "服务", nav: "services", show: showServices },
  targets: { title: "主机管理", nav: "targets", show: showTargets },
  metrics: { title: "主机详情", nav: "targets", show: showMetrics },
  cluster: { title: "集群详情", nav: "targets", show: showCluster },
  network: { title: "网络", nav: "network", show: showNetwork },
  alerts: { title: "告警", nav: "alerts", show: showAlerts },
  event: { title: "事件详情", nav: "alerts", show: showEvent },
  settings: { title: "采集设置", nav: "settings", show: showSampling },
};

function routeQuery() {
  return new URLSearchParams(desktop ? location.hash.slice(1) : location.search);
}

function routeCollectionKey(view, query) {
  const target = query.get("id") || "";
  switch (view) {
    case "targets": return JSON.stringify([view, query.get("tab") === "clusters" ? "clusters" : "hosts", query.get("cursor") || ""]);
    case "services": return JSON.stringify([view, query.get("source") || "", query.get("target") || ""]);
    case "metrics": return JSON.stringify([view, target]);
    case "network": return JSON.stringify([view, target, Object.hasOwn(networkTabs, query.get("tab")) ? query.get("tab") : "interfaces"]);
    case "cluster": return JSON.stringify([view, target, Object.hasOwn(clusterTabs, query.get("tab")) ? query.get("tab") : "namespaces"]);
    default: return "";
  }
}

let collectionRoute = "";
let collection;
const recentCollections = new Map();

function resetCollection(route) {
  if (collectionRoute === route) return;
  collectionRoute = route;
  collection?.detach();
  collection = null;
}

function clearCollections() {
  resetCollection("");
  recentCollections.clear();
}

function bindDefaultTarget(view, query, target) {
  if (query.get("id")) return;
  const values = { ...Object.fromEntries(query), id: target.id };
  history.replaceState(null, "", locationFor(view, values));
  collectionRoute = routeCollectionKey(view, new URLSearchParams(values));
}

function navigate(href, replace = false) {
  if (dialog.open) closeDialog();
  closeVersion();
  history[replace ? "replaceState" : "pushState"](null, "", href);
  render();
}

async function render({ quiet = false } = {}) {
  const id = ++generation;
  routeRead?.abort();
  routeRead = new AbortController();
  const { signal } = routeRead;
  const query = routeQuery();
  const requested = query.get("view");
  const legacyServiceFilter = !requested && ["source", "target", "state", "namespace", "q"].some((field) => query.has(field));
  const view = Object.hasOwn(views, requested) ? requested : legacyServiceFilter ? "services" : "targets";
  const route = views[view];
  resetCollection(routeCollectionKey(view, query));
  document.title = `${route.title} | Imon`;
  for (const item of document.querySelectorAll("[data-nav]")) {
    if (item.dataset.nav === route.nav) item.setAttribute("aria-current", "page");
    else item.removeAttribute("aria-current");
  }
  if (!content.firstChild) content.replaceChildren(heading(route.title));
  if (!quiet) {
    content.setAttribute("aria-busy", "true");
    content.inert = true;
    routeProgress.hidden = false;
  }
  try {
    await route.show(query, id, signal);
  } catch (error) {
    if (id === generation && !quiet) insert(id, heading(route.title), notice(error.message, true), button("重新加载", render));
  } finally {
    if (id === generation) {
      content.setAttribute("aria-busy", "false");
      content.inert = false;
      routeProgress.hidden = true;
    }
  }
}

function insert(id, ...nodes) {
  if (generation === id) {
    closeHostActionsIn(content);
    content.replaceChildren(...nodes.filter(Boolean));
  }
}

workspace.addEventListener("click", (event) => {
  const anchor = event.target.closest("a");
  if (!anchor || event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey ||
      anchor.target || anchor.hasAttribute("download")) return;
  if (desktop ? !anchor.getAttribute("href")?.startsWith("#?") : anchor.origin !== location.origin || anchor.pathname !== "/") return;
  event.preventDefault();
  navigate(desktop ? anchor.hash : anchor.pathname + anchor.search);
});
window.addEventListener("popstate", () => {
  if (!workspace.hidden) {
    if (dialog.open) closeDialog();
    closeVersion();
    render();
  }
});
document.addEventListener("visibilitychange", () => {
  if (!document.hidden && !workspace.hidden) {
    refreshUnread();
    collection?.wake();
  }
});
window.addEventListener("focus", () => collection?.wake());

function pageList(path, values = {}, onPage = () => {}, routePage = null) {
  const region = element("div", { class: "list-page" });
  let revision = 0;
  let current = routePage?.cursor || null;
  let loaded = false;
  async function load(cursor, quiet = false) {
    current = cursor;
    const id = ++revision;
    if (!quiet || !loaded) {
      closeHostActionsIn(region);
      region.replaceChildren(notice("正在加载…"));
    }
    try {
      const page = await get(path + params({ ...values, cursor, limit: 50 }));
      if (id !== revision) return;
      const last = quiet && region.querySelector(".inventory");
      const scroll = last && { left: last.scrollLeft, top: last.scrollTop };
      const restoreFocus = last && last.contains(document.activeElement);
      closeHostActionsIn(region);
      region.replaceChildren(...onPage(page || {}));
      loaded = true;
      if (cursor || page?.next_cursor) {
        const move = routePage ? routePage.navigate : load;
        region.append(element("div", { class: "actions" },
          cursor ? button("首页", () => move(null)) : null,
          page?.next_cursor ? button("下一页", () => move(page.next_cursor)) : null));
      }
      const inventory = scroll && region.querySelector(".inventory");
      if (inventory) {
        inventory.scrollTo(scroll);
        if (restoreFocus) inventory.focus({ preventScroll: true });
      }
    } catch (error) {
      if (id === revision && (!quiet || !loaded)) region.replaceChildren(notice(error.message, true), button("重新加载", () => load(cursor)));
    }
  }
  region.snapshotReady = load(current);
  region.refreshSnapshot = () => load(current, true);
  return region;
}

function items(page) {
  if (Array.isArray(page)) return page;
  return Array.isArray(page?.items) ? page.items : [];
}

function snapshotItems(page) {
  return items(page).map((row) => row.payload ? { ...row.payload, object_key: row.object_key } : row);
}

async function allPages(path, values = {}, options = {}) {
  const result = [];
  const cursors = new Set();
  let cursor;
  do {
    if (options.signal?.aborted) break;
    const page = await get(path + params({ ...values, cursor, limit: 200 }), options);
    result.push(...items(page));
    cursor = page?.next_cursor;
    if (cursor) {
      const fingerprint = JSON.stringify(cursor);
      if (cursors.has(fingerprint)) break;
      cursors.add(fingerprint);
    }
  } while (cursor);
  return result;
}

function showTask(jobID, options = {}) {
  if (!jobID) throw new Error("接口缺少任务编号。");
  const feedback = notice("正在读取任务…");
  const result = element("div");
  const taskView = element("div", { class: "stack" }, feedback, result,
    element("div", { class: "form-actions" }, button("关闭", closeDialog)));
  const startedIn = generation;
  showDialog(options.title || "任务进度", taskView);
  const taskVisible = () => taskView.isConnected && dialog.open;
  const refresh = async () => {
    if (!taskVisible() && !options.refreshAfterSuccess) return;
    try {
      const job = await get(`/jobs/${key(jobID)}`);
      const state = job.status === "running" ? "running_job" : job.status;
      const results = job.results || {};
      const waiting = state === "success" && results.convergence === "pending";
      const pending = ["queued", "running"].includes(job.status) || waiting;
      const delay = waiting ? 5000 : 700;
      if (!pending && state === "success") options.refreshAfterSuccess?.();
      if (!taskVisible()) {
        if (pending && options.refreshAfterSuccess) setTimeout(refresh, delay);
        return;
      }
      const migrating = options.updating && job.error_code === "helper_migration_required";
      const taskError = migrating ? "" : job.error_code === "ssh_network_unreachable" ? sshTestErrors.ssh_network_unreachable
        : sourceErrorLabel(job.error_code);
      feedback.replaceChildren(chip(migrating ? "awaiting_admin" : state, state === "success" && results.convergence ? "副本数已写入" : undefined),
        taskError || "");
      const details = [];
      if (results.installed_version) {
        const displayVersion = results.installed_display_version ||
          `${!options.updating && localVersion?.current ? `${localVersion.current} ` : ""}${results.installed_version.slice(0, 5)}`;
        details.push(["已安装版本", displayVersion]);
      }
      if (results.requested_version) {
        const displayVersion = results.requested_display_version ||
          `${localVersion?.current ? `${localVersion.current} ` : ""}${results.requested_version.slice(0, 5)}`;
        details.push([options.updating ? "更新版本" : "目标版本", displayVersion]);
      }
      for (const [group, value] of Object.entries(results)) {
        if (["upload_only", "unbind_requested", "selected_service_units", "requested_units_sha256", "installed_version",
          "installed_display_version", "requested_version", "requested_display_version"].includes(group)) continue;
        let entry;
        if (group === "convergence") entry = ["达标状态", convergenceText[value] || display(value)];
        else if (group === "observed_state") entry = ["实际服务状态", statusText[value] || display(value)];
        else if (group === "convergence_error") entry = ["达标检查结果", sourceErrorLabel(value)];
        else if (group === "firewall_status") entry = ["授权状态", firewallStatusText[value] || display(value)];
        else if (group === "unbound") entry = ["绑定状态", "已解绑"];
        else if (group === "cleanup_confirmed") entry = ["已确认清理", value === "true" || value === true ? "是" : "否"];
        else entry = [groupLabel(group), value && typeof value === "object" ? display(value.status || value.error_code || value) : value || "成功"];
        details.push(entry);
      }
      if (job.stage_path) details.push(["远端脚本", job.stage_path]);
      result.replaceChildren(...(details.length ? [pairs(details)] : []));
      if (job.error_code === "administrator_required" && options.administrator) {
        if (options.operation === "uninstall") {
          result.append(notice("当前授权需要由目标主机管理员卸载。可使用管理员 SSH 凭据继续。"));
        }
        result.append(button("使用管理员凭据", options.administrator));
      }
      if (migrating && options.administrator) {
        result.append(notice("已安装的辅助程序还不支持自行更新。请由管理员授权一次，后续版本会由辅助程序自行安装。"),
          button("使用管理员凭据迁移", options.administrator, "primary"));
      }
      if (options.configureHostAccess && ["permission_denied", "service_not_granted", "service_helper_upgrade_required"].includes(job.error_code)) {
        result.append(button("配置主机授权", () => options.configureHostAccess(job.error_code)));
      }
      if (job.manual_upload_available && options.upload) {
        if (!options.updating) {
          result.append(notice(options.operation === "uninstall"
            ? "是否上传维护脚本，由你在目标主机上以管理员身份执行？"
            : "自动安装授权需要管理员权限。是否上传维护脚本，由你在目标主机上执行？"));
        }
        result.append(button(options.updating ? "上传迁移脚本" : "上传脚本", async (event) => {
            const upload = event.currentTarget;
            upload.disabled = true;
            try {
              const next = await options.upload(jobID);
              if (taskView.isConnected && dialog.open) showTask(next?.job_id, { ...options, upload: undefined, administrator: undefined });
            } catch (error) {
              if (taskView.isConnected && dialog.open) formError(feedback, error);
              upload.disabled = false;
            }
          }, options.updating ? "secondary" : "primary"));
      }
      if (!job.manual_upload_available && job.download_path === `/api/v1/jobs/${key(jobID)}/firewall-script`) {
        result.append(desktop ? button("保存维护脚本", async (event) => {
          const save = event.currentTarget;
          save.disabled = true;
          try {
            const outcome = await desktop.saveFirewallScript({ path: job.download_path, filename: "firewall-maintain.sh" });
            if (outcome?.saved) notify("已保存维护脚本。");
          } catch (error) {
            formError(feedback, error);
          } finally {
            save.disabled = false;
          }
        }) : element("a", { href: job.download_path, class: "action secondary", download: "firewall-maintain.sh" }, "下载维护脚本"));
      }
      if (job.command) {
        const operation = options.updating ? "迁移" : options.operation === "install" ? "安装"
          : options.operation === "uninstall" ? "卸载" : "清理";
        const command = element("pre", { class: "command" }, job.command);
        const fullCommand = element("details", {}, element("summary", {}, "查看完整命令"), command);
        const steps = element("ol", {},
          element("li", {}, "以 root 或具有 sudo 权限的账户登录目标主机，先单独运行 ", element("code", {}, "/bin/sh"), " 并按回车。"),
          element("li", {}, `进入 /bin/sh 后，复制并执行${operation}命令。完成后点击「重新检测授权」。`));
        result.append(steps,
          button("复制命令", async () => {
          try {
            await navigator.clipboard.writeText(job.command);
          } catch {
            fullCommand.open = true;
            const selection = window.getSelection();
            const range = document.createRange();
            range.selectNodeContents(command);
            selection.removeAllRanges();
            selection.addRange(range);
            if (!document.execCommand("copy")) {
              notify("命令已选中，请使用系统复制快捷键。");
              return;
            }
          }
          notify("已复制命令。");
        }), fullCommand);
      }
      if (options.verify && (job.command || state === "unknown" || (options.retryVerify && state === "failed" && !migrating))) {
        result.append(button("重新检测授权", options.verify));
      }
      if (pending) setTimeout(refresh, delay);
      else {
        if (options.complete && state === "success") await options.complete(job, result);
        if (taskView.isConnected && generation === startedIn) render();
      }
    } catch (error) {
      if (taskView.isConnected && dialog.open) {
        formError(feedback, error);
        feedback.append(button("重试", refresh));
      }
    }
  };
  refresh();
}

function groupLabel(group) {
  return ({ host_metrics: "主机性能", metrics: "主机性能", os_info: "系统版本",
    probe: "采集连接", systemd: "主机服务", services: "服务", ...networkTabs, ...clusterTabs })[group] || group;
}

const collectionDebounce = 250;
const collectionRetention = 120000;

function mountCollection(id, scope, refresh, ready) {
  if (id !== generation) return;
  const slot = content.querySelector(".collection-status");
  if (!slot) return;
  const scopeKey = JSON.stringify(scope);
  const now = performance.now();
  for (const [savedKey, saved] of recentCollections) {
    if (saved !== collection && now - saved.detachedAt > collectionRetention) recentCollections.delete(savedKey);
  }
  if (collection?.scope !== scopeKey) {
    collection?.detach();
    collection = recentCollections.get(scopeKey) || trackCollection(scope, scopeKey);
    recentCollections.set(scopeKey, collection);
  }
  collection.attach(slot, () => {
    if (id === generation) refresh();
  }, ready);
}

function waitForCollection(ms, signal) {
  if (signal.aborted) return Promise.resolve();
  return new Promise((resolve) => {
    const finish = () => {
      clearTimeout(timer);
      signal.removeEventListener("abort", finish);
      resolve();
    };
    const timer = setTimeout(finish, ms);
    signal.addEventListener("abort", finish, { once: true });
  });
}

function formatCollectionCountdown(seconds) {
  return seconds < 60 ? `${seconds}s` : `${Math.floor(seconds / 60)}m${seconds % 60}s`;
}

function trackCollection(scope, scopeKey) {
  let current;
  let sending;
  let batch;
  let nextCollectionAt = Infinity;
  const cursors = new Set();

  function paint(view) {
    if (current !== view) return;
    const progress = batch?.pending.size ? { completed: batch.total - batch.pending.size, total: batch.total } : view.active;
    const seconds = Math.max(0, Math.ceil((nextCollectionAt - performance.now()) / 1000));
    const label = progress ? `采集${progress.completed}/${progress.total}`
      : Number.isFinite(seconds) ? `下次采集:${formatCollectionCountdown(seconds)}` : "";
    if (!view.slot) return;
    view.slot.hidden = !label;
    if (progress || !label) {
      if (view.displayed === label) return;
      view.slot.replaceChildren(...(progress ? [
        element("span", { class: "collection-spinner", "aria-hidden": "true" }), element("span", {}, label),
      ] : []));
    } else {
      let action = view.slot.querySelector(".collection-now");
      if (!action) {
        action = element("button", { type: "button", class: "collection-now", title: "立即采集",
          onclick: () => requestNow(view) });
        view.slot.replaceChildren(action);
      }
      if (view.displayed !== label) action.textContent = label;
      action.disabled = view.following || Boolean(sending || batch);
    }
    view.displayed = label;
  }

  function reload(view) {
    if (current === view && view.slot?.isConnected) view.refresh();
  }

  function submitBatch(cursor, dueOnly) {
    // Keep dispatched POSTs until their job IDs arrive; aborting fetch cannot undo enqueue.
    sending ||= api("/collection-requests", "POST", { ...scope, ...(cursor && { cursor }), due_only: dueOnly }, { keepSession: true })
      .then((result) => {
        const pending = new Set(items(result?.jobs).map(({ job_id }) => job_id).filter(Boolean));
        batch = { total: pending.size, pending, next: result?.next_cursor, dueOnly };
      }).finally(() => { sending = null; });
    return sending;
  }

  async function followBatches(view, dueOnly = true) {
    if (view.following) return;
    view.following = true;
    paint(view);
    const { signal } = view.abort;
    let observedJobs = false;
    try {
      if (!batch && !sending) {
        cursors.clear();
        await submitBatch(undefined, dueOnly);
      } else if (sending) {
        await sending;
      }
      while (!signal.aborted && batch) {
        paint(view);
        if (batch.pending.size) {
          observedJobs = true;
          await waitForCollection(750, signal);
          if (signal.aborted) return;
          const statuses = await Promise.all([...batch.pending].map(async (id) => {
            try {
              const job = await get(`/jobs/${key(id)}`, { signal });
              return [id, job?.status && !["queued", "running"].includes(job.status)];
            } catch (error) {
              return [id, error.status === 404 || error.status === 410];
            }
          }));
          if (signal.aborted) return;
          const before = batch.pending.size;
          for (const [id, done] of statuses) if (done) batch.pending.delete(id);
          if (batch.pending.size !== before) {
            paint(view);
            reload(view);
            refreshUnread();
          }
          if (batch.pending.size) continue;
        }
        const next = batch.next;
        if (!next || cursors.has(next)) {
          batch = null;
          break;
        }
        cursors.add(next);
        await submitBatch(next, batch.dueOnly);
      }
    } catch {
      if (current === view) batch = null;
      // Remote failures are reported in alert events, not in the page header.
    } finally {
      view.following = false;
      if (current === view) {
        paint(view);
        if (observedJobs || view.due || !dueOnly) wake();
      }
    }
  }

  function requestNow(view) {
    if (current !== view || view.active || view.following || sending || batch) return;
    clearTimeout(view.debounceTimer);
    view.debounceTimer = null;
    view.due = false;
    followBatches(view, false);
  }

  function requestDue(view) {
    if (!view.ready || !view.due || view.following || view.debounceTimer) return;
    view.debounceTimer = setTimeout(() => {
      view.debounceTimer = null;
      if (current === view && view.due) {
        view.due = false;
        followBatches(view);
      }
    }, collectionDebounce);
  }

  async function readStatus(view) {
    const { signal } = view.abort;
    if (!view.started || signal.aborted || view.statusPending) return;
    view.statusPending = true;
    try {
      const result = await get("/collection-status" + params(scope), { signal });
      if (signal.aborted) return;
      const active = result?.active?.total > 0 ? result.active : null;
      if (view.active && (!active || active.completed !== view.active.completed || active.total < view.active.total)) {
        reload(view);
        refreshUnread();
      }
      view.active = active;
      const now = performance.now();
      const deadline = (at) => Number.isFinite(at) && Number.isFinite(result?.server_now)
        ? now + Math.max(0, at - result.server_now) : Infinity;
      nextCollectionAt = Math.min(deadline(result?.next_run_at), deadline(result?.next_foreground_at));
      view.due = result?.foreground_due === true;
      requestDue(view);
    } catch {
      if (signal.aborted) return;
      view.active = null;
      if (nextCollectionAt <= performance.now()) nextCollectionAt = Infinity;
      view.due = false;
    } finally {
      view.statusPending = false;
      if (!signal.aborted) {
        paint(view);
        const wait = view.active ? 1000 : Math.max(250, Math.min(15000, nextCollectionAt - performance.now()));
        view.statusTimer = setTimeout(() => readStatus(view), wait);
      }
    }
  }

  function wake() {
    if (!current?.started) return;
    clearTimeout(current.statusTimer);
    readStatus(current);
  }

  return {
    scope: scopeKey,
    detachedAt: 0,
    attach(node, callback, ready) {
      const view = current ||= { abort: new AbortController() };
      view.slot = node;
      view.refresh = callback;
      view.displayed = null;
      if (!view.started) {
        if (nextCollectionAt <= performance.now()) nextCollectionAt = Infinity;
        view.started = true;
        view.tick = setInterval(() => paint(view), 1000);
        wake();
      }
      paint(view);
      Promise.resolve(ready).then(() => {
        if (view.ready || current !== view || view.slot !== node || !node.isConnected) return;
        view.ready = true;
        if (batch || sending) followBatches(view);
        requestDue(view);
      });
    },
    wake,
    detach() {
      if (!current) return;
      current.abort.abort();
      clearTimeout(current.statusTimer);
      clearTimeout(current.debounceTimer);
      clearInterval(current.tick);
      current = null;
      this.detachedAt = performance.now();
    },
  };
}

const isCluster = (target) => ["cluster", "kubernetes"].includes(target?.kind);
const isDeployment = (service) => ["cluster", "deployment", "kubernetes"].includes(service?.source);

function serviceCollectionProblem({ error_code: code, cluster }) {
  if (code === "permission_denied") return cluster
    ? "Kubernetes 服务采集权限不足：请为绑定的身份授予 Deployment 的 list 权限。"
    : "systemd 服务采集权限不足：请检查绑定的 SSH 用户是否能通过 systemctl 读取系统服务。";
  if (code === "authentication_failed") return cluster
    ? "Kubernetes 认证失败：请检查集群凭据。"
    : "SSH 认证失败：请检查主机连接配置和 SSH 私钥。";
  if (["timeout", "timed_out"].includes(code)) return "服务采集超时。";
  if (code === "connection_failed") return "连接失败：请检查主机或集群的连通性。";
  return `服务采集失败（${sourceErrorLabel(code)}）。`;
}

// Keep the action affordance visible when a service is observed but cannot be
// changed yet.  This makes the reason actionable instead of silently dropping
// the button for transitional or incomplete states.
function serviceActionReason(service, action) {
  if (!service.authorized) return "未配置该服务的启停授权。";
  if (service.stale) return "采集数据已过期，请等待下一次成功采集。";
  if (!service.state) return "尚未采集到可确认的服务状态。";
  if (service.state === "starting") return "服务正在启动中，暂不支持操作。";
  if (action === "stop" && service.state !== "running") return "仅运行中的服务可以停止。";
  if (action === "start" && !["stopped", "failed"].includes(service.state)) return "仅停止或失败的服务可以启动。";
  if (isDeployment(service) && action === "start" && service.desired !== 0) {
    return "Deployment 当前副本数不为 0，不能执行启动。";
  }
  return "";
}

function serviceResourceHint(service, metric) {
  if (Number.isFinite(service[metric])) return null;
  if (isDeployment(service)) return "未采集到 Kubernetes Metrics API 指标。";
  return metric === "cpu_percent"
    ? "尚未形成两次有效 CPU 计数，或目标未提供 CPU 记账。"
    : "目标未提供 systemd MemoryCurrent 记账。";
}

const serviceColumns = { name: "服务", target: "目标", state: "状态", cpu: "CPU", memory: "内存" };
const servicePageSize = 50;

function scrollServiceList(values, columns, renderRow, empty, signal) {
  const inventory = listTable("服务列表", columns, [], empty);
  const body = inventory.querySelector("tbody");
  const emptyRow = body.firstElementChild;
  body.replaceChildren();
  const feedback = element("div", { class: "service-list-feedback", role: "status" });
  inventory.append(feedback);
  const region = element("div", { class: "list-page" }, inventory);
  const shown = new Set();
  let nextCursor;
  let loaded = false;
  let failed = false;
  let pending;
  let queuedRefresh;

  function nearEnd() {
    if (!signal.aborted && region.isConnected && nextCursor && !pending && !failed &&
        inventory.scrollHeight - inventory.scrollTop - inventory.clientHeight <= 160) load(nextCursor);
  }

  async function read(cursor, quiet) {
    const limit = quiet ? Math.max(servicePageSize, shown.size) : servicePageSize;
    if (!quiet || !loaded) feedback.textContent = "正在加载…";
    const rows = [];
    let next = cursor;
    try {
      // Refresh all loaded rows together. Reuse larger API batches when the user has scrolled deep.
      do {
        const page = await get("/services" + params({ ...values, cursor: next, limit: Math.min(200, limit - rows.length) }), { signal });
        if (signal.aborted) return;
        const batch = items(page);
        rows.push(...batch);
        next = batch.length && page?.next_cursor !== next ? page?.next_cursor : null;
      } while (quiet && next && rows.length < limit);

      const scroll = { left: inventory.scrollLeft, top: inventory.scrollTop };
      const restoreFocus = !cursor && loaded && body.contains(document.activeElement);
      if (!cursor) shown.clear();
      const fragment = document.createDocumentFragment();
      for (const service of rows) {
        if (shown.has(service.id)) continue;
        shown.add(service.id);
        fragment.append(tableRow(renderRow(service)));
      }
      if (cursor) body.append(fragment);
      else body.replaceChildren(shown.size ? fragment : emptyRow);
      nextCursor = next;
      loaded = true;
      failed = false;
      feedback.replaceChildren();
      if (!cursor) {
        inventory.scrollTo(scroll);
        if (restoreFocus) inventory.focus({ preventScroll: true });
      }
    } catch (error) {
      if (signal.aborted || (quiet && loaded)) return;
      failed = true;
      feedback.replaceChildren(notice(error.message, true), button("重新加载", () => load(cursor, quiet)));
    }
  }

  function load(cursor, quiet = false) {
    if (signal.aborted) return Promise.resolve();
    pending ||= read(cursor, quiet).finally(() => {
      pending = null;
      if (!signal.aborted) requestAnimationFrame(nearEnd);
    });
    return pending;
  }

  const resize = new ResizeObserver(nearEnd);
  resize.observe(inventory);
  signal.addEventListener("abort", () => resize.disconnect(), { once: true });
  inventory.addEventListener("scroll", nearEnd, { passive: true, signal });
  region.snapshotReady = load(null);
  region.refreshSnapshot = () => {
    if (!pending) return load(null, true);
    queuedRefresh ||= pending.then(() => {
      queuedRefresh = null;
      return load(null, true);
    });
    return queuedRefresh;
  };
  return region;
}

async function showServices(query, id, signal) {
  const targets = await allPages("/targets", {}, { signal });
  if (id !== generation) return;
  const source = ["host", "cluster"].includes(query.get("source")) ? query.get("source") : "";
  const requestedSort = query.get("sort");
  const sort = Object.hasOwn(serviceColumns, requestedSort) ? requestedSort : "name";
  const direction = query.get("direction") === "desc" ? "desc" : "asc";
  const fields = {
    source: select("source", [["", "全部"], ["host", "宿主机"], ["cluster", "Kubernetes"]], source),
    target: select("target", [["", "全部"], ...targets
      .filter((target) => !source || isCluster(target) === (source === "cluster"))
      .map((target) => [target.id, target.name])], query.get("target")),
    state: select("state", [["", "全部"], ...serviceStates.map((state) => [state, statusText[state]])], query.get("state")),
    namespace: input("namespace", query.get("namespace"), { placeholder: "命名空间" }),
    q: input("q", query.get("q"), { type: "search", placeholder: "搜索服务" }),
  };
  const filters = element("form", { class: "toolbar" },
    control("部署来源", fields.source), control("主机 / 集群", fields.target),
    control("状态", fields.state), control("命名空间", fields.namespace), control("名称", fields.q),
    submit("筛选"));
  const serviceLocation = (field, order) => locationFor("services", {
    ...Object.fromEntries(new FormData(filters)), sort: field, direction: order,
  });
  filters.addEventListener("submit", (event) => {
    event.preventDefault();
    navigate(serviceLocation(sort, direction));
  });
  fields.source.addEventListener("change", () => {
    fields.target.value = "";
    if (fields.source.value === "host") fields.namespace.value = "";
    filters.requestSubmit();
  });
  for (const field of [fields.target, fields.state]) field.addEventListener("change", () => filters.requestSubmit());
  fields.namespace.disabled = source === "host";
  const selected = targets.find((target) => target.id === fields.target.value);
  const requestedTarget = query.get("target");
  const scope = { view: "services", ...(source && { source }), ...(requestedTarget && { target_id: requestedTarget }) };
  const summary = element("div");
  const observations = (list) => list.filter((target) =>
    (!requestedTarget || requestedTarget === target.id) && (!source || isCluster(target) === (source === "cluster")))
    .map((target) => ({ ...target.summary?.service_observation, name: target.name, cluster: isCluster(target) }));
  let lastObservations = observations(targets);
  const getObserved = () => lastObservations.filter((row) => row.observed_at != null);
  function emptyServiceList() {
    if (!targets.length) return ["尚未绑定主机或集群", meta(link("前往主机管理", locationFor("targets")))];
    if (requestedTarget && !selected) return ["此主机或集群已解绑或不存在。"];
    const observed = getObserved();
    if (observed.some((row) => row.has_items)) return ["未找到匹配项"];
    if (lastObservations.some((row) => row.error_code)) return ["当前没有可显示的服务数据"];
    return observed.length && observed.length === lastObservations.length ? ["采集成功，未发现数据"] : ["暂无已采集数据"];
  }
  const columns = Object.entries(serviceColumns).map(([field, label]) => {
    const active = field === sort;
    const next = active ? direction === "asc" ? "desc" : "asc" : ["cpu", "memory"].includes(field) ? "desc" : "asc";
    const icon = element("span", { class: "service-sort-icon", "aria-hidden": "true" },
      active ? direction === "asc" ? "↑" : "↓" : "↕");
    return element("th", { scope: "col", "aria-sort": active ? direction === "asc" ? "ascending" : "descending" : null },
      button([label, icon], () => navigate(serviceLocation(field, next)), "", {
        class: "service-sort", "data-sort": field, title: `${label}：${next === "asc" ? "升序" : "降序"}`,
      }));
  });
  const empty = element("span", { "data-service-empty": true }, emptyServiceList());
  const listing = scrollServiceList({
    source, state: fields.state.value, namespace: fields.namespace.disabled ? "" : fields.namespace.value, q: fields.q.value,
    host_id: isCluster(selected) || (!selected && source === "cluster") ? "" : requestedTarget,
    cluster_id: isCluster(selected) || (!selected && source === "cluster") ? requestedTarget : "",
    sort, direction,
  }, [...columns, "操作"], (service) => {
    const deployment = isDeployment(service);
    const state = element("div", {}, chip(service.state),
      service.stale ? meta("数据已过期") : null,
      meta(`采集 ${formatTime(service.observed_at)}`));
    const action = service.state === "running" ? "stop" : "start";
    // Keep an action placeholder for an unknown state so the user can see
    // why it is unavailable; never send an action until a concrete state is
    // observed and passes the backend preconditions.
    const canDisplay = serviceStates.includes(service.state) || !service.state;
    const explanation = serviceActionReason(service, action);
    const disabled = Boolean(explanation);
    return [element("div", {}, service.name,
      meta(deployment ? `Deployment · 副本 ${display(service.ready)} / ${display(service.desired)}` : "systemd")),
      element("div", {}, service.target_name, service.namespace ? meta(service.namespace) : null), state,
      element("span", { class: "service-resource", title: serviceResourceHint(service, "cpu_percent") }, Number.isFinite(service.cpu_percent) ? formatPercent(service.cpu_percent) : null),
      element("span", { class: "service-resource", title: serviceResourceHint(service, "memory_bytes") }, Number.isFinite(service.memory_bytes) ? formatBytes(service.memory_bytes) : null),
      element("div", { class: "actions" },
        canDisplay ? button(action === "start" ? "启动" : "停止", () => serviceAction(service.id, action),
          "secondary", { disabled, title: disabled ? explanation : null }) : null,
        button("创建告警", () => ruleEditor({ selector: serviceSelector(service), objectTitle: service.name })))];
  }, empty, signal);
  let readVersion = 0;
  function publishObservations() {
    if (generation !== id) return;
    const observed = getObserved();
    const latest = observed.reduce((time, row) => Math.max(time, row.observed_at), 0);
    const detail = latest ? `最近成功 ${formatTime(latest)}${observed.some((row) => row.stale) ? " · 有数据已过期" : ""}` : "";
    const failed = lastObservations.filter((row) => row.error_code);
    const shown = failed.slice(0, 2).map((row) => `${row.name}：${serviceCollectionProblem(row)}`);
    if (failed.length > shown.length) shown.push(`另有 ${failed.length - shown.length} 个目标采集失败，详见告警事件。`);
    summary.replaceChildren(...(detail ? [notice(detail)] : []), ...(shown.length ? [notice(shown.join(" "), true)] : []));
    const empty = listing.querySelector("[data-service-empty]");
    if (empty) empty.replaceChildren(...emptyServiceList());
  }
  const ready = listing.snapshotReady.then(publishObservations);
  insert(id, heading("服务", [], true), filters, summary, listing);
  if (!requestedTarget || selected) mountCollection(id, scope, async () => {
    const revision = ++readVersion;
    const before = allPages("/targets", {}, { signal }).catch(() => null);
    await listing.refreshSnapshot();
    const updated = await before;
    if (revision !== readVersion) return;
    if (updated) lastObservations = observations(updated);
    publishObservations();
  }, ready);
}

function serviceSelector(service) {
  return isDeployment(service)
    ? { target_id: service.target_id, metric: "deployment_state", uid: service.uid || service.object_key, namespace: service.namespace, name: service.name }
    : { target_id: service.target_id, metric: "systemd_state", unit: service.unit || service.name };
}

async function serviceAction(serviceID, action) {
  const view = generation;
  try {
    const service = await get(`/services/${key(serviceID)}`);
    if (generation !== view) return;
    if (!service.authorized || service.stale) throw new Error("服务权限或采集状态已变化，请刷新列表。");
    const expected = action === "stop" ? service.state === "running" : ["stopped", "failed"].includes(service.state);
    if (!expected || (isDeployment(service) && action === "start" && service.desired !== 0)) {
      throw new Error("服务状态已变化，请刷新列表后重新确认。");
    }
    const label = action === "start" ? "启动" : "停止";
    const deployment = isDeployment(service);
    const needsReplicas = deployment && action === "start" && !service.resume_replicas;
    const replicas = input("replicas", 1, { type: "number", min: 1, max: 2147483647, required: true });
    const description = element("div", { class: "stack" },
      pairs([["对象", service.name], ["位置", [service.target_name, service.namespace].filter(Boolean).join(" / ")],
        ["当前状态", statusText[service.state]], ["动作", label],
        ...(deployment && !needsReplicas ? [["目标副本数", action === "stop" ? 0 : service.resume_replicas]] : [])]),
      needsReplicas ? control("启动副本数", replicas) : null);
    actionForm(`确认${label}服务`, description, label, async (confirmUnknown) => {
      if (needsReplicas && !replicas.reportValidity()) return;
      const request = { action, connection_rev: service.connection_rev, expected_state: service.state };
      if (deployment) request.expected_desired = service.desired;
      if (needsReplicas) request.replicas = Number(replicas.value);
      if (confirmUnknown) request.confirm_unknown = true;
      const job = await api(`/services/${key(service.id || serviceID)}/actions`, "POST", request);
      showTask(job?.job_id, { title: `${service.name} / ${label}`,
        configureHostAccess: service.uses_host_login ? (errorCode) => {
          const updating = errorCode === "service_helper_upgrade_required";
          requestFirewallMaintenance({ id: service.target_id, name: service.target_name }, updating ? "update" : "install");
        } : null,
      });
    }, action === "stop" ? "danger" : "primary", "已在目标上核实当前服务状态，确认执行此操作");
  } catch (error) {
    notify(error.message);
  }
}

function detailsFor(target) {
  return locationFor(isCluster(target) ? "cluster" : "metrics", { id: target.id });
}

function targetAlert(target) {
  return button("创建告警", () => ruleEditor({ selector: { target_id: target.id, metric: "target_reachable" } }));
}

function sourceErrorLabel(code) {
  return ({
    firewall_unreadable: "防火墙读取未授权", permission_denied: "权限不足", authentication_failed: "认证失败",
    host_key_mismatch: "主机密钥不匹配", identity_changed: "目标身份已变化", timed_out: "采集超时",
    timeout: "采集超时", command_unavailable: "缺少采集命令", administrator_required: "需要管理员权限",
    helper_migration_required: "旧版主机授权需要迁移",
    maintenance_package_unavailable: "当前应用缺少所需的授权维护包。",
    helper_update_not_installed: "未确认主机上有已安装的授权，请重新检测。",
    helper_update_invalid: "主机拒绝了授权更新包，请检查发布签名和文件完整性。",
    helper_update_architecture: "授权更新包与主机架构不匹配。",
    helper_update_stale: "主机已有同版本或更高版本的授权。",
    helper_update_host_state: "主机上的授权状态异常，请重新检测授权。",
    service_not_granted: "当前主机授权无法启停该服务。",
    service_helper_upgrade_required: "请更新主机授权后重试。",
    service_action_not_run: "主机未执行该服务操作，请检查 systemd 状态。",
    service_units_unconfirmed: "尚未核实所选服务的授权。请在主机上执行维护命令后重新检测。",
    state_changed: "服务状态已变化，请重新采集后再试。",
    object_changed: "服务已变更或未加载，请重新采集后再试。",
    connection_failed: "连接主机失败。请检查 SSH 连接后重试。",
    result_unconfirmed: "尚未确认远端操作结果。",
  })[code] || code;
}

function openHostRow(event) {
  if (event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
  const row = event.currentTarget;
  const hostLink = row.querySelector(".host-name-link");
  const clickedLink = hostLink.contains(event.target);
  if (!clickedLink && event.target.closest("td:last-child, a, button, input, select, textarea, label, summary, [contenteditable]")) return;

  const selection = window.getSelection();
  // Keep pointer selection in place while allowing keyboard activation of the link.
  if ((!clickedLink || event.detail > 0) && selection?.rangeCount && !selection.isCollapsed && selection.getRangeAt(0).intersectsNode(row)) {
    event.preventDefault();
    return;
  }
  if (!clickedLink) navigate(hostLink.getAttribute("href"));
}

let activeHostActions;

function closeHostActionsIn(region) {
  if (activeHostActions && region.contains(activeHostActions.trigger)) activeHostActions.close();
}

function hostActions(target) {
  const commands = [];
  const authorizationStatus = target.firewall_authorization_status;
  // Only an explicit authorization probe can distinguish native privileges
  // from a readable snapshot produced by the installed helper.
  if (authorizationStatus !== "native") {
    const action = authorizationStatus === "installed" ? "uninstall" : "install";
    if (action === "uninstall" && target.host_authorization_update_available) {
      commands.push(["更新授权", () => requestFirewallMaintenance(target, "update")]);
    }
    commands.push([action === "install" ? "安装授权" : "卸载授权", () => requestFirewallMaintenance(target, action)]);
  }
  commands.push(
    ["创建告警", () => ruleEditor({ selector: { target_id: target.id, metric: "target_reachable" } })],
    ["解绑", () => unbind(target)],
  );
  const menu = element("div", { class: "host-action-menu", role: "menu", "aria-label": "主机操作", hidden: true });
  let openListeners;
  const close = (restoreFocus = false) => {
    if (menu.hidden) return;
    openListeners.abort();
    openListeners = null;
    activeHostActions = null;
    menu.hidden = true;
    trigger.setAttribute("aria-expanded", "false");
    if (restoreFocus) trigger.focus({ preventScroll: true });
  };
  const entries = commands.map(([label, action]) => button(label, () => {
    close(true);
    action();
  }, label === "解绑" || label === "卸载授权" ? "danger" : "secondary", { role: "menuitem", tabindex: -1 }));
  const open = (index = 0) => {
    if (!menu.hidden) return;
    activeHostActions?.close();
    activeHostActions = { trigger, close };
    menu.hidden = false;
    trigger.setAttribute("aria-expanded", "true");
    const anchor = trigger.getBoundingClientRect();
    const gap = 5;
    const maxLeft = document.documentElement.clientWidth - menu.offsetWidth - gap;
    const maxTop = document.documentElement.clientHeight - menu.offsetHeight - gap;
    const top = anchor.bottom + gap <= maxTop ? anchor.bottom + gap : anchor.top - menu.offsetHeight - gap;
    menu.style.left = `${Math.max(gap, Math.min(anchor.right - menu.offsetWidth, maxLeft))}px`;
    menu.style.top = `${Math.max(gap, Math.min(top, maxTop))}px`;
    entries[index].focus({ preventScroll: true });
    openListeners = new AbortController();
    const { signal } = openListeners;
    document.addEventListener("click", (event) => {
      if (!menu.contains(event.target) && !trigger.contains(event.target)) close();
    }, { signal });
    document.addEventListener("scroll", (event) => {
      if (!menu.contains(event.target)) close();
    }, { capture: true, signal });
    window.addEventListener("resize", () => close(), { signal });
  };
  const arrow = element("span", { class: "dropdown-arrow", "aria-hidden": "true" });
  const trigger = button(["操作", arrow], () => menu.hidden ? open() : close(), "secondary", {
    class: "action secondary host-action-trigger", "aria-haspopup": "menu", "aria-expanded": "false",
    onkeydown: (event) => {
      if (event.key === "ArrowDown" || event.key === "ArrowUp") {
        event.preventDefault();
        open(event.key === "ArrowUp" ? entries.length - 1 : 0);
      }
    },
  });
  menu.append(...entries);
  menu.addEventListener("keydown", (event) => {
    const current = entries.indexOf(document.activeElement);
    switch (event.key) {
      case "Escape": event.preventDefault(); close(true); return;
      case "Tab": close(true); return;
      case "ArrowDown": event.preventDefault(); entries[(current + 1) % entries.length].focus(); return;
      case "ArrowUp": event.preventDefault(); entries[(current + entries.length - 1) % entries.length].focus(); return;
      case "Home": case "End":
        event.preventDefault();
        entries[event.key === "Home" ? 0 : entries.length - 1].focus();
    }
  });
  const actions = element("div", { class: "actions host-actions" },
    button("编辑", () => editTarget(target)), trigger, menu);
  actions.addEventListener("focusout", (event) => {
    if (!actions.contains(event.relatedTarget)) close();
  });
  return actions;
}

function clusterActions(target) {
  const commands = [
    ["创建告警", () => ruleEditor({ selector: { target_id: target.id, metric: "target_reachable" } })],
    ["解绑", () => unbind(target)],
  ];
  const menu = element("div", { class: "host-action-menu", role: "menu", "aria-label": "集群操作", hidden: true });
  let openListeners;
  const close = (restoreFocus = false) => {
    if (menu.hidden) return;
    openListeners?.abort();
    openListeners = null;
    activeHostActions = null;
    menu.hidden = true;
    trigger.setAttribute("aria-expanded", "false");
    if (restoreFocus) trigger.focus({ preventScroll: true });
  };
  const entries = commands.map(([label, action]) => button(label, () => {
    close(true);
    action();
  }, label === "解绑" ? "danger" : "secondary", { role: "menuitem", tabindex: -1 }));
  const open = (index = 0) => {
    if (!menu.hidden) return;
    activeHostActions?.close();
    activeHostActions = { trigger, close };
    menu.hidden = false;
    trigger.setAttribute("aria-expanded", "true");
    const anchor = trigger.getBoundingClientRect();
    const gap = 5;
    const maxLeft = document.documentElement.clientWidth - menu.offsetWidth - gap;
    const maxTop = document.documentElement.clientHeight - menu.offsetHeight - gap;
    const top = anchor.bottom + gap <= maxTop ? anchor.bottom + gap : anchor.top - menu.offsetHeight - gap;
    menu.style.left = `${Math.max(gap, Math.min(anchor.right - menu.offsetWidth, maxLeft))}px`;
    menu.style.top = `${Math.max(gap, Math.min(top, maxTop))}px`;
    entries[index].focus({ preventScroll: true });
    openListeners = new AbortController();
    const { signal } = openListeners;
    document.addEventListener("click", (event) => {
      if (!menu.contains(event.target) && !trigger.contains(event.target)) close();
    }, { signal });
    document.addEventListener("scroll", (event) => {
      if (!menu.contains(event.target)) close();
    }, { capture: true, signal });
    window.addEventListener("resize", () => close(), { signal });
  };
  const arrow = element("span", { class: "dropdown-arrow", "aria-hidden": "true" });
  const trigger = button(["操作", arrow], () => menu.hidden ? open() : close(), "secondary", {
    class: "action secondary host-action-trigger", "aria-haspopup": "menu", "aria-expanded": "false",
    onkeydown: (event) => {
      if (event.key === "ArrowDown" || event.key === "ArrowUp") {
        event.preventDefault();
        open(event.key === "ArrowUp" ? entries.length - 1 : 0);
      }
    },
  });
  menu.append(...entries);
  menu.addEventListener("keydown", (event) => {
    const current = entries.indexOf(document.activeElement);
    switch (event.key) {
      case "Escape": event.preventDefault(); close(true); return;
      case "Tab": close(true); return;
      case "ArrowDown": event.preventDefault(); entries[(current + 1) % entries.length].focus(); return;
      case "ArrowUp": event.preventDefault(); entries[(current + entries.length - 1) % entries.length].focus(); return;
      case "Home": case "End":
        event.preventDefault();
        entries[event.key === "Home" ? 0 : entries.length - 1].focus();
    }
  });
  const actions = element("div", { class: "actions host-actions" },
    button("编辑", () => editTarget(target)), trigger, menu);
  actions.addEventListener("focusout", (event) => {
    if (!actions.contains(event.relatedTarget)) close();
  });
  return actions;
}

async function showTargets(query, id) {
  const tab = query.get("tab") === "clusters" ? "clusters" : "hosts";
  const cursor = query.get("cursor") || null;
  const columns = tab === "hosts"
    ? ["主机", "CPU", "内存", "磁盘", "系统", "SSH 状态", "操作"]
    : ["集群", "API 状态", "就绪节点", "异常 Pod", "操作"];
  const listing = pageList("/targets", { kind: tab === "hosts" ? "host" : "cluster" }, (page) => {
    const filtered = items(page).filter((target) => isCluster(target) === (tab === "clusters"));
    const rows = filtered.map((target) => {
      const cluster = isCluster(target);
      const summary = target.summary || {};
      const state = target.connection_status || target.status || summary.connection_status || "pending";
      const connection = chip(state);
      const nodeLink = target.node_link;
      const linkedName = [nodeLink?.cluster_name, nodeLink?.node_name || nodeLink?.node_uid].filter(Boolean).join(" / ");
      const linkStatus = nodeLink?.status === "missing" ? "原节点已不存在，请重新关联"
        : nodeLink?.status === "pending" ? "等待采集确认关联节点" : linkedName ? `关联节点 ${linkedName}` : "";
      const details = detailsFor(target);
      const name = element("a", { class: "host-name-link", href: details }, target.name);
      const first = element("div", { class: "host-identity" }, name,
        !cluster && target.address ? element("div", { class: "host-address" }, target.address) : null,
        linkStatus ? meta(linkStatus) : null);
      const ready = summary.nodes_ready ?? summary.ready_nodes;
      const total = summary.nodes_total ?? summary.total_nodes;
      const nodes = Number.isInteger(ready) && Number.isInteger(total) ? `${ready} / ${total}` : undefined;
      const actions = cluster ? clusterActions(target) : hostActions(target);
      if (cluster) return tableRow([first, connection, nodes, summary.abnormal_pods, actions], { class: "host-row", onclick: openHostRow });
      const hostControls = target.host_authorization_up_to_date
        ? element("div", {}, actions, meta(authorizationCurrentText)) : actions;
      const os = summary.os_info;
      const usage = summary.host_usage;
      const cells = [first, usageCell(usage?.cpu, true), usageCell(usage?.memory), usageCell(usage?.disk),
        element("div", {}, display(os?.display_name)), element("div", {}, connection), hostControls];
      return tableRow(cells, { class: "host-row", onclick: openHostRow });
    });
    return [listTable(tab === "hosts" ? "主机列表" : "集群列表", columns, rows, tab === "hosts" ? "尚未绑定 Linux 主机" : "尚未绑定 Kubernetes 集群")];
  }, { cursor, navigate: (next) => navigate(locationFor("targets", { tab: tab === "clusters" ? tab : "", cursor: next })) });
  insert(id,
    heading("主机管理", [button("绑定主机", () => targetEditor("host"), "primary"),
      button("绑定集群", () => targetEditor("cluster"), "primary")], true),
    tabs([["hosts", "主机", locationFor("targets")], ["clusters", "Kubernetes 集群", locationFor("targets", { tab: "clusters" })]], tab),
    listing);
  mountCollection(id, { view: tab, limit: 50, ...(cursor && { cursor }) }, listing.refreshSnapshot, listing.snapshotReady);
}

function configFields(cluster, initial = {}, optional = false) {
  const config = initial.config || {};
  if (cluster) {
    const kubeconfig = input("kubeconfig", config.kubeconfig, { required: !optional, placeholder: "<本机 kubeconfig 绝对路径>" });
    const context = input("context", config.context, { required: !optional, placeholder: "<Context 名称>" });
    return {
      node: element("div", { class: "fields" }, localFileField("kubeconfig 引用", kubeconfig, true), control("Context", context, true)),
      config: () => ({ kubeconfig: kubeconfig.value.trim(), context: context.value.trim() }),
    };
  }
  function endpoint(prefix, given = {}, label = "") {
    const address = input(`${prefix}_address`, given.address, { required: !optional && !label, placeholder: label ? "<跳板地址>" : "<主机地址>" });
    const port = input(`${prefix}_port`, given.port ?? 22, { type: "number", required: !optional && !label, min: 1, max: 65535 });
    const user = input(`${prefix}_user`, given.user, { required: !optional && !label, placeholder: "<登录用户>" });
    const keyFile = input(`${prefix}_key_file`, given.key_file, { required: !optional && !label, placeholder: "<本机私钥路径，如 ~/.ssh/id_ed25519>" });
    const requireJumpFields = () => {
      if (label) for (const entry of [port, user, keyFile]) entry.required = Boolean(address.value.trim());
    };
    address.addEventListener("input", requireJumpFields);
    requireJumpFields();
    return {
      node: element("div", { class: "fields" }, control("SSH 地址", address), control("端口", port),
        control("登录用户", user), privateKeyField("SSH 私钥引用", keyFile, true)),
      value: () => ({ address: address.value.trim(), port: Number(port.value), user: user.value.trim(),
        key_file: keyFile.value.trim() }),
    };
  }
  const ssh = endpoint("ssh", config.ssh);
  const jump = endpoint("jump", config.jump, "跳板");
  return {
    node: element("div", { class: "stack" }, ssh.node,
      element("details", { open: Boolean(config.jump) }, element("summary", {}, "SSH 跳板（可选）"), jump.node)),
    config: () => ({ ssh: ssh.value(), ...(jump.value().address ? { jump: jump.value() } : {}) }),
  };
}

async function editTarget(target) {
  const message = notice("正在读取连接配置…");
  showDialog(`编辑${isCluster(target) ? "集群" : "主机"}`, element("div", { class: "stack" }, message,
    element("div", { class: "form-actions" }, button("取消", closeDialog))));
  try {
    const detail = await get(targetPath(target.id));
    if (!message.isConnected || !dialog.open) return;
    targetEditor(detail.kind, detail);
  } catch (failure) {
    if (message.isConnected && dialog.open) formError(message, failure);
  }
}

const sshTestErrors = {
  credential_unreadable: "SSH 私钥文件读不到。请核对运行 Imon 的电脑上的文件路径和读取权限。",
  credential_invalid: "所选文件不是可用的 SSH 私钥。请确认没有选中 .pub 公钥文件。",
  credential_passphrase_required: "这把 SSH 私钥有加密口令，当前连接只支持无需口令的私钥。",
  authentication_failed: "SSH 服务器拒绝了私钥认证。请核对登录用户名，以及该用户是否已授权对应公钥。",
  dns_failed: "主机地址无法解析。请核对主机名或跳板地址。",
  connection_failed: "未能建立 SSH 连接。请核对主机地址、SSH 端口和网络连通性。",
  ssh_network_unreachable: "运行 Imon 的电脑无法到达 SSH 主机。请检查本机到 SSH 主机（或跳板）的网络连接。如果 macOS 终端能连通，请从终端启动 Web 版，并检查「系统设置 → 隐私与安全性 → 本地网络」。",
  timeout: "SSH 连接测试超时。请核对 SSH 端口、网络连通性和服务器响应。",
  command_unavailable: "已连接到 SSH，但系统缺少检查所需的命令。请确认目标是 Linux 并使用 systemd。",
};

function targetEditor(kind, existing) {
  const cluster = isCluster({ kind });
  const title = existing ? `编辑${cluster ? "集群" : "主机"}` : `绑定${cluster ? "集群" : "主机"}`;
  const error = notice("");
  const connectionHint = "保存时自动测试连接。";
  const feedback = notice("");
  const name = input("name", existing?.name, { required: true, maxlength: 160 });
  const change = checkbox("change_connection", false);
  const connection = configFields(cluster, existing);
  const approval = element("div", { class: "stack" });
  const panels = element("div", { class: "stack" }, connection.node, approval);
  const save = submit(existing ? "保存修改" : "保存绑定");
  const acknowledged = checkbox("confirm_unknown", false);
  const confirmation = element("label", { class: "checks", hidden: true }, acknowledged,
    "已在目标上核实上次操作的影响，确认修改连接配置");
  let ticket;
  let tested;
  let approvedExec;
  let execApprovalPending = false;
  let revision = 0;
  let testingRevision;
  let saving = false;
  const modifiesConnection = () => !existing || change.checked;
  const updateSave = () => {
    save.disabled = saving || testingRevision === revision || execApprovalPending || (!confirmation.hidden && !acknowledged.checked);
  };
  const payload = () => ({ kind: cluster ? "cluster" : "host", name: name.value.trim(), ...connection.config(),
    ...(approvedExec ? { kube_exec_sha256: approvedExec } : {}) });
  const connectionSignature = (request) => {
    const { name: _name, ...config } = request;
    return JSON.stringify(config);
  };
  const invalidate = () => {
    revision += 1;
    ticket = undefined;
    tested = undefined;
    execApprovalPending = false;
    approval.replaceChildren();
    confirmation.hidden = true;
    acknowledged.checked = false;
    updateSave();
    feedback.textContent = modifiesConnection() ? connectionHint : "单独修改显示名称无需重新测试。";
  };
  const connectionChanged = () => {
    approvedExec = undefined;
    invalidate();
  };
  const isCurrent = (requestRev) => requestRev === revision && form.isConnected && dialog.open;
  async function showExecApproval(request, requestRev) {
    approvedExec = undefined;
    const { kubeconfig, context } = request;
    const result = await api("/targets/kube-exec-approval", "POST", { kubeconfig, context });
    if (!isCurrent(requestRev)) return;
    if (!/^[a-f0-9]{64}$/.test(result?.sha256)) throw new Error("未获取登录插件的校验摘要。");
    execApprovalPending = true;
    updateSave();
    feedback.textContent = "确认登录插件后才能测试此连接。";
    approval.append(notice("此 Context 会在运行客户端的电脑上执行 kubeconfig 指定的登录插件。请先核对该文件和插件，再确认执行。"),
      pairs([["登录插件配置摘要", result.sha256]]),
      element("div", { class: "actions" }, button("信任插件并重新测试", () => {
        if (!isCurrent(requestRev)) return;
        approvedExec = result.sha256;
        execApprovalPending = false;
        testConnection();
      }, "primary")));
  }
  async function testConnection(confirmationToken) {
    if (saving || testingRevision === revision || !form.reportValidity()) return;
    const request = payload();
    invalidate();
    formError(error, null);
    feedback.textContent = "正在测试连接…";
    const requestRev = revision;
    testingRevision = requestRev;
    updateSave();
    try {
      const result = await api("/targets/test", "POST", { ...request,
        ...(existing ? { target_id: existing.id } : {}),
        ...(confirmationToken ? { ssh_confirmation_token: confirmationToken } : {}),
      });
      if (!isCurrent(requestRev)) return;
      const returned = result?.test_ticket || result?.test_token;
      if (!returned) throw new Error("连接测试未返回保存票据。");
      ticket = returned;
      tested = connectionSignature(request);
      feedback.textContent = result.warnings?.length
        ? "连接测试通过，部分资源权限受限：" + display(result.warnings)
        : "连接测试通过，可以保存。";
      await persist();
    } catch (failure) {
      if (!isCurrent(requestRev)) return;
      if (!cluster && failure.code === "host_key_confirmation_required") {
        const { role, address, fingerprint, confirmation_token: token } = failure.details || {};
        if (["target", "jump"].includes(role) && address && fingerprint && token) {
          feedback.textContent = `首次连接${role === "jump" ? "跳板" : "主机"}，请核对 SSH 主机指纹。`;
          approval.append(pairs([["连接地址", address], ["SHA-256 指纹", fingerprint]]),
            element("div", { class: "actions" }, button("已核对指纹，继续连接", () => {
              if (isCurrent(requestRev)) testConnection(token);
            }, "primary")));
          return;
        }
      }
      if (cluster && failure.code === "exec_approval_required") {
        try {
          await showExecApproval(request, requestRev);
          return;
        } catch (approvalError) {
          failure = approvalError;
        }
      }
      if (isCurrent(requestRev)) {
        invalidate();
        const hint = !cluster && Object.hasOwn(sshTestErrors, failure.code) ? sshTestErrors[failure.code] : null;
        formError(error, hint ? `${hint}（${failure.code}）` : failure);
      }
    } finally {
      if (testingRevision === requestRev) {
        testingRevision = undefined;
        updateSave();
      }
    }
  }
  const form = element("form", { class: "stack" }, control("显示名称", name),
    existing ? element("label", { class: "checks" }, change, "修改连接配置") : null,
    panels, feedback, error, confirmation,
    existing ? element("div", { class: "actions" },
      !cluster ? button("关联节点", () => linkNode(existing)) : null,
      button("服务启停授权", () => serviceAuthorization(existing))) : null,
    element("div", { class: "form-actions" }, button("取消", closeDialog), save));
  const toggle = () => {
    panels.hidden = Boolean(existing) && !change.checked;
    for (const field of panels.querySelectorAll("input, textarea, button")) field.disabled = panels.hidden;
    connectionChanged();
  };
  toggle();
  change.addEventListener("change", toggle);
  connection.node.addEventListener("input", connectionChanged);
  name.addEventListener("input", () => {
    if (!ticket) feedback.textContent = modifiesConnection() ? connectionHint : "单独修改显示名称无需重新测试。";
  });
  acknowledged.addEventListener("change", updateSave);
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    if (save.disabled) return;
    if (modifiesConnection() && tested !== connectionSignature(payload())) testConnection();
    else persist();
  });
  async function persist() {
    const withConnection = modifiesConnection();
    const request = withConnection ? payload() : { name: name.value.trim() };
    if (withConnection && (!ticket || tested !== connectionSignature(request))) {
      formError(error, "连接参数已变化，请重新测试。");
      return;
    }
    if (withConnection) request.test_token = ticket;
    if (existing) request.connection_rev = existing.connection_rev;
    if (existing && withConnection && acknowledged.checked) request.confirm_unknown = true;
    saving = true;
    const controls = [...form.querySelectorAll("input, textarea, button:not([type=submit])")].filter((entry) => !entry.disabled);
    for (const entry of controls) entry.disabled = true;
    updateSave();
    formError(error, null);
    try {
      await api(existing ? targetPath(existing.id) : "/targets", existing ? "PATCH" : "POST", request);
      if (!form.isConnected || !dialog.open) return;
      closeDialog();
      notify(existing ? "已保存修改。" : "已保存绑定。");
      if (withConnection) clearCollections();
      navigate(locationFor("targets", { tab: cluster ? "clusters" : "hosts" }), true);
    } catch (failure) {
      formError(error, failure);
      if (failure.code === "test_required") invalidate();
      if (existing && withConnection && failure.code === "result_unconfirmed") {
        acknowledged.checked = false;
        confirmation.hidden = false;
      }
    } finally {
      saving = false;
      for (const entry of controls) entry.disabled = false;
      updateSave();
    }
  }
  showDialog(title, form);
}

function unbind(target) {
  const host = !isCluster(target);
  const remove = async (confirmUnknown) => {
    const job = await api(targetPath(target.id) + params({ confirm_unknown: confirmUnknown }), "DELETE");
    if (job?.job_id) {
      showTask(job.job_id, unbindTaskOptions(target, () => remove(confirmUnknown)));
      return;
    }
    if (dialog.open) closeDialog();
    notify("已解绑。");
    render();
  };
  actionForm(`确认解绑 ${target.name}？`, element("p", {},
    host ? "确认后自动清理主机上的 Imon 授权和暂存脚本。清理未验证时会保留绑定，解绑后停止采集、暂停关联规则并保留历史告警。"
      : "解绑后将停止采集并暂停关联规则，历史告警仍可查看。"),
  "确认解绑", remove, "danger", "已核实目标上的上次操作，确认解绑并保留历史记录");
}

async function linkNode(target) {
  const state = element("div", { class: "stack" }, notice("正在加载集群…"), button("返回编辑", () => targetEditor(target.kind, target)));
  showDialog("关联 Kubernetes 节点", state);
  try {
    const clusters = (await allPages("/targets")).filter(isCluster);
    if (!state.isConnected || !dialog.open) return;
    const cluster = select("cluster_id", [["", "选择集群"], ...clusters.map((item) => [item.id, item.name])], target.node_link?.cluster_id);
    const node = select("node_uid", [["", "选择节点"]], "");
    const error = notice("");
    const save = submit("保存关联");
    node.required = true;
    cluster.required = true;
    let revision = 0;
    const fillNodes = async () => {
      const id = ++revision;
      node.replaceChildren(element("option", { value: "" }, "选择节点"));
      formError(error, null);
      save.disabled = true;
      if (!cluster.value) return;
      try {
        const records = await allPages(`/clusters/${key(cluster.value)}/resources/nodes`);
        if (id !== revision) return;
        node.append(...snapshotItems(records).filter((entry) => entry.uid || entry.object_key)
          .map((entry) => element("option", { value: entry.uid || entry.object_key }, entry.name)));
        if (cluster.value === target.node_link?.cluster_id) node.value = target.node_link.node_uid;
        save.disabled = false;
      } catch (failure) {
        if (id === revision) formError(error, failure);
      }
    };
    cluster.addEventListener("change", fillNodes);
    const remove = button("解除关联", async () => {
      try {
        await api(targetPath(target.id) + "/node-link", "DELETE");
        closeDialog();
        notify("已解除节点关联。");
        render();
      } catch (failure) {
        formError(error, failure);
      }
    }, "danger");
    const form = element("form", { class: "stack" }, control("集群", cluster), control("节点", node), error,
      element("div", { class: "form-actions" }, button("返回编辑", () => targetEditor(target.kind, target)),
        target.node_link ? remove : null, save));
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      save.disabled = true;
      try {
        await api(targetPath(target.id) + "/node-link", "PUT", { cluster_id: cluster.value, node_uid: node.value });
        closeDialog();
        notify("已保存节点关联。");
        render();
      } catch (failure) {
        formError(error, failure);
        save.disabled = false;
      }
    });
    state.replaceChildren(form);
    fillNodes();
  } catch (failure) {
    state.prepend(notice(failure.message, true));
  }
}

async function serviceAuthorization(target) {
  const state = element("div", { class: "stack" }, notice("正在读取授权和已采集服务…"),
    button("返回编辑", () => targetEditor(target.kind, target)));
  showDialog("服务启停授权", state);
  const path = targetPath(target.id) + "/service-authorization";
  const cluster = isCluster(target);
  try {
    const [authorization, services] = await Promise.all([
      get(path).catch((error) => { if (error.status !== 404) throw error; return null; }),
      allPages("/services", cluster ? { cluster_id: target.id } : { host_id: target.id }),
    ]);
    if (!state.isConnected || !dialog.open) return;
    const grant = authorization?.authorization || authorization;
    const check = checkbox("external_manager_checked", grant?.external_manager_checked);
    const sshUser = input("ssh_user", "", { required: true, placeholder: "<启停授权用户>" });
    const sshKey = input("ssh_key_file", "", { required: true, placeholder: "<本机 SSH 私钥绝对路径>" });
    const credentials = cluster ? configFields(true) : {
      node: element("div", { class: "fields" }, control("SSH 登录用户", sshUser, true), privateKeyField("SSH 私钥引用", sshKey, true)),
      config: () => ({ ssh: { user: sshUser.value.trim(), key_file: sshKey.value.trim() } }),
    };
    const save = submit("保存授权");
    const error = notice("");
    const chosen = new Set(grant?.object_ids || []);
    const objects = element("fieldset", { class: "checks" }, element("legend", {}, "允许启停的服务"),
      services.map((service) => {
        const option = checkbox("object_ids", chosen.has(service.id));
        option.value = service.id;
        return element("label", {}, option, [service.namespace, service.name].filter(Boolean).join(" / "));
      }),
      services.length ? null : notice("先完成一次采集才能选择服务。"));
    save.disabled = !services.length;
    const revoke = button("撤销授权", async () => {
      try {
        await api(path, "DELETE");
        closeDialog();
        notify("已撤销启停授权。");
        render();
      } catch (failure) {
        formError(error, failure);
      }
    }, "danger");
    const form = element("form", { class: "stack" },
      notice("请使用独立的服务启停凭据，并先在目标上为所选对象配置权限。"),
      credentials.node, objects,
      cluster ? element("label", { class: "checks" }, check, "已确认所选 Deployment 由管理员独立管理副本数") : null,
      error, element("div", { class: "form-actions" }, button("返回编辑", () => targetEditor(target.kind, target)),
        grant?.object_ids?.length ? revoke : null, save));
    check.required = cluster;
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const objectIDs = new FormData(form).getAll("object_ids");
      if (!objectIDs.length) {
        formError(error, "至少选择一个服务，或使用撤销授权。");
        return;
      }
      save.disabled = true;
      try {
        await api(path, "PUT", { connection_rev: target.connection_rev, credential_ref: credentials.config(),
          object_ids: objectIDs, ...(cluster ? { external_manager_checked: check.checked } : {}) });
        closeDialog();
        notify("已保存服务启停授权。");
        render();
      } catch (failure) {
        formError(error, failure);
        save.disabled = false;
      }
    });
    state.replaceChildren(form);
  } catch (failure) {
    state.prepend(notice(failure.message, true));
  }
}

const firewallStatusText = { installed: "已安装", uninstalled: "未安装", native: "已有权限", unknown: "待核实", pending: "检查中" };
const authorizationCurrentText = "已是最新版本";

function refreshHostAuthorization(targetID) {
  if (workspace.hidden) return;
  const query = routeQuery();
  const view = query.get("view") || "targets";
  if (view === "targets" && query.get("tab") !== "clusters") {
    render({ quiet: true });
  } else if (["network", "metrics", "services"].includes(view)) {
    const selected = query.get(view === "services" ? "target" : "id");
    if (!selected || selected === targetID) render({ quiet: true });
  }
}

function firewallTaskOptions(target, action, label, updating) {
  const title = `${label} / ${target.name}`;
  const options = {
    title,
    operation: action,
    label,
    updating,
    administrator: () => firewallCredentialForm(target, action, options),
    upload: (id) => api(`${targetPath(target.id)}/maintenance/upload`, "POST", { action, auto_job_id: id }),
    verify: () => firewallCredentialForm(target, "verify", options),
    retryVerify: true,
    refreshAfterSuccess: () => refreshHostAuthorization(target.id),
  };
  return options;
}

async function requestFirewallMaintenance(target, operation) {
  const updating = operation === "update";
  const label = updating ? "更新授权" : operation === "install" ? "安装授权" : "卸载授权";
  try {
    const job = await api(`/hosts/${key(target.id)}/firewall-maintenance`, "POST", { action: operation });
    showTask(job?.job_id, firewallTaskOptions(target, operation, label, updating));
  } catch (error) {
    notify(error.message);
  }
}

function firewallCredentialForm(target, action, options) {
  const verifying = action === "verify";
  const label = verifying ? "重新检测授权" : options.updating ? "迁移授权" : options.label;
  const adminUser = input("admin_user", "", { placeholder: "<管理员登录用户>" });
  const adminKey = input("admin_key_file", "", { placeholder: "<本机管理员 SSH 私钥绝对路径>" });
  const useAdmin = verifying ? checkbox("use_admin", false) : null;
  const error = notice("");
  const commit = submit(label);
  const fields = element("div", { class: "fields" }, control("管理员登录用户", adminUser, true), privateKeyField("管理员私钥引用", adminKey, true));
  const update = () => {
    const enabled = !verifying || useAdmin.checked;
    fields.hidden = !enabled;
    adminUser.required = enabled;
    adminKey.required = enabled;
    for (const field of fields.querySelectorAll("input, textarea, button")) field.disabled = !enabled;
  };
  useAdmin?.addEventListener("change", update);
  update();
  const form = element("form", { class: "stack" },
    notice(verifying
      ? "重新读取目标主机上的授权状态；如普通 SSH 账号权限不足，可选择独立管理员凭据。"
      : "使用独立管理员 SSH 凭据执行授权操作；该凭据仅用于本次远程操作。"),
    verifying ? element("label", { class: "checks" }, useAdmin, "使用独立管理员 SSH 凭据") : null,
    fields, error, element("div", { class: "form-actions" }, button("取消", closeDialog), commit));
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    commit.disabled = true;
    try {
      const job = await api(`/hosts/${key(target.id)}/firewall-maintenance`, "POST", {
        action,
        ...((!verifying || useAdmin.checked) ? {
          credential_ref: { ssh: { user: adminUser.value.trim(), key_file: adminKey.value.trim() } },
        } : {}),
      });
      if (form.isConnected && dialog.open) showTask(job?.job_id, verifying ? { ...options, updating: false } : options);
    } catch (failure) {
      formError(error, failure);
      commit.disabled = false;
    }
  });
  showDialog(`${label} / ${target.name}`, form);
}

function firewallAuthorizationInfo(target, offerUpdate = false) {
  const state = meta("主机授权：检查中");
  const statusLine = offerUpdate ? element("div", { class: "actions" }, state) : state;
  get(`/hosts/${key(target.id)}/firewall-authorization`).then((authorization) => {
    const status = firewallStatusText[authorization.status] || firewallStatusText.unknown;
    const available = authorization.update_available && authorization.available_display_version
      ? `可用版本 ${authorization.available_display_version}` : "";
    state.textContent = [`主机授权：${status}`, authorization.installed_display_version,
      authorization.up_to_date ? authorizationCurrentText : available].filter(Boolean).join(" · ");
    if (offerUpdate && authorization.update_available) {
      statusLine.append(button("更新授权", () => requestFirewallMaintenance(target, "update")));
    }
  }).catch(() => {
    state.textContent = "主机授权：待核实";
  });
  return statusLine;
}

function unbindTaskOptions(target, retry, action = "uninstall") {
  const title = `解绑 / ${target.name}`;
  const verify = () => unbindCleanupForm(target, retry, "verify");
  return {
    title, operation: action, verify, retryVerify: action === "verify",
    administrator: action === "uninstall" ? () => unbindCleanupForm(target, retry, "uninstall") : undefined,
    upload: action === "uninstall" ? (id) => api(`${targetPath(target.id)}/maintenance/upload`, "POST", { action, auto_job_id: id }) : undefined,
    complete: async (job, result) => {
      const facts = job.results || {};
      if (facts.unbound === "true" || facts.unbound === true) {
        closeDialog();
        notify("已解绑。");
        render();
      } else if (facts.firewall_status === "uninstalled" && (facts.cleanup_confirmed === "true" || facts.cleanup_confirmed === true)) {
        result.append(notice("已确认清理，正在解绑…"));
        await retry();
      } else {
        result.append(notice("尚未确认清理，主机绑定仍保留。"), button("重新检测授权", verify),
          button("使用管理员凭据清理", () => unbindCleanupForm(target, retry, "uninstall")));
      }
    },
  };
}

function unbindCleanupForm(target, retry, action) {
  const verifying = action === "verify";
  const label = verifying ? "重新检测授权" : "清理授权";
  const adminUser = input("admin_user", "", { required: true, placeholder: "<管理员登录用户>" });
  const adminKey = input("admin_key_file", "", { required: true, placeholder: "<本机管理员 SSH 私钥绝对路径>" });
  const toggle = checkbox("auto", !verifying);
  const error = notice("");
  const commit = submit(label);
  const fields = element("div", { class: "fields" }, control("管理员登录用户", adminUser, true), privateKeyField("管理员私钥引用", adminKey, true));
  const update = () => {
    fields.hidden = !toggle.checked;
    for (const field of fields.querySelectorAll("input, textarea, button")) field.disabled = !toggle.checked;
  };
  toggle.addEventListener("change", update);
  update();
  const form = element("form", { class: "stack" },
    notice("清理验证成功后继续解绑。若普通 SSH 账号读不到授权文件，请使用独立的管理员 SSH 凭据。"),
    verifying ? element("label", { class: "checks" }, toggle, "使用独立管理员 SSH 凭据") : null,
    fields, error, element("div", { class: "form-actions" }, button("取消", closeDialog), commit));
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    commit.disabled = true;
    try {
      const job = await api(`/hosts/${key(target.id)}/firewall-maintenance`, "POST", {
        action, ...(toggle.checked ? { credential_ref: { ssh: { user: adminUser.value.trim(), key_file: adminKey.value.trim() } } } : {}),
      });
      if (form.isConnected && dialog.open) showTask(job?.job_id, unbindTaskOptions(target, retry, action));
    } catch (failure) {
      formError(error, failure);
      commit.disabled = false;
    }
  });
  showDialog(`${label} / ${target.name}`, form);
}

async function showSampling(_query, id) {
  const settings = await get("/sampling-settings");
  const poll = checkbox("poll_enabled", settings.poll_enabled);
  const numeric = [
    ["host_interval", "主机性能与服务（秒）", 10, 86400],
    ["network_interval", "主机网络（秒）", 10, 86400],
    ["cluster_interval", "Kubernetes 资源（秒）", 10, 86400],
    ["timeout", "采集超时（秒）", 10, 900],
  ];
  const edits = numeric.map(([field, title, min, max]) =>
    [title, input(field, settings[field] ?? (field === "timeout" ? settings.round_timeout : undefined),
      { type: "number", min, max, required: true })]);
  const error = notice("");
  const save = submit();
  const form = element("form", { class: "stack settings-form" },
    element("label", { class: "checks" }, poll, "定时采集（当前页面及有效告警规则）"),
    element("div", { class: "fields" }, edits.map(([title, edit]) => control(title, edit))),
    error, element("div", { class: "form-actions" }, save));
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    save.disabled = true;
    try {
      await api("/sampling-settings", "PUT", {
        poll_enabled: poll.checked, revision: settings.revision,
        ...Object.fromEntries(edits.map(([, edit]) => [edit.name, Number(edit.value)])),
      });
      clearCollections();
      notify("已保存采集设置。");
      if (id === generation) render();
    } catch (failure) {
      formError(error, failure);
      save.disabled = false;
    }
  });
  insert(id, heading("采集设置"), form);
}

async function detailTargets(cluster, query) {
  const targets = (await allPages("/targets")).filter((entry) => isCluster(entry) === cluster);
  const requested = query.get("id");
  return [targets, requested ? targets.find((entry) => entry.id === requested) : targets[0]];
}

function snapshotTime(page, fallback) {
  const time = page?.observed_at;
  const latest = time ?? fallback;
  return `最后采集：${latest == null ? "—" : formatTime(latest)}${page?.stale ? " · 数据已过期" : ""}`;
}

function updateSnapshotTime(node, page, fallback) {
  node.textContent = snapshotTime(page, fallback);
}

function targetContext(targets, target, label = "选择主机") {
  const entries = targets.map((entry) => [entry.id, entry.name]);
  if (!target) entries.unshift(["", label]);
  const node = select("id", entries, target?.id ?? "");
  node.setAttribute("aria-label", label);
  if (!target) node.options[0].disabled = true;
  // Let the native select handle interaction while the title text can truncate.
  const control = element("span", { class: "target-context-control" },
    element("span", { class: "target-context-name", "aria-hidden": "true" }, target?.name ?? label),
    element("span", { class: "dropdown-arrow", "aria-hidden": "true" }), node);
  return { node, control };
}

function snapshotContext() {
  return element("span", { class: "context-last-success" }, "最后采集：—");
}

function snapshotEmpty(page, message) {
  return page.observed_at == null ? "暂无已采集数据" : message;
}

function selectedTargetChange(selectControl, view, additional = {}) {
  selectControl.node.addEventListener("change", () => navigate(locationFor(view, { id: selectControl.node.value, ...additional })));
}

function sparkline(series, from, to, maximum, label, maxGap) {
  const points = series.filter((point) => Number.isFinite(point.at)).sort((a, b) => a.at - b.at);
  if (!points.some((point) => Number.isFinite(point.value))) return meta("暂无趋势");
  const ymax = maximum ?? Math.max(1, ...points.map((point) => Number.isFinite(point.value) ? point.value : 0));
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("class", "spark");
  svg.setAttribute("viewBox", "0 0 100 32");
  svg.setAttribute("preserveAspectRatio", "none");
  svg.setAttribute("role", "img");
  svg.setAttribute("aria-label", label);
  let segment = [];
  const add = () => {
    if (!segment.length) return;
    if (segment.length === 1) {
      const dot = document.createElementNS(svg.namespaceURI, "circle");
      dot.setAttribute("cx", segment[0][0]);
      dot.setAttribute("cy", segment[0][1]);
      dot.setAttribute("r", "1");
      svg.append(dot);
    } else {
      const line = document.createElementNS(svg.namespaceURI, "polyline");
      line.setAttribute("points", segment.map((point) => point.join(",")).join(" "));
      svg.append(line);
    }
    segment = [];
  };
  let previous;
  for (const point of points) {
    if (!Number.isFinite(point.value)) {
      add();
      continue;
    }
    if (previous !== undefined && point.at - previous > maxGap) add();
    segment.push([1 + (point.at - from) * 98 / (to - from), 31 - Math.max(0, Math.min(point.value / ymax, 1)) * 30]);
    previous = point.at;
  }
  add();
  return svg;
}

async function showMetrics(query, id) {
  const [targets, target] = await detailTargets(false, query);
  if (id !== generation) return;
  if (!target) {
    insert(id, heading("主机详情"), notice("请选择仍绑定的主机。"), link("主机管理", locationFor("targets"), "secondary"));
    return;
  }
  bindDefaultTarget("metrics", query, target);
  const spans = [[3600000, "最近 1 小时"], [21600000, "最近 6 小时"], [86400000, "最近 24 小时"], [604800000, "最近 7 天"]];
  const span = spans.find(([value]) => String(value) === query.get("span"))?.[0] ?? spans[0][0];
  const to = Date.now();
  const from = to - span;
  const host = targetContext(targets, target);
  const lastSuccess = snapshotContext();
  const range = select("span", spans, span);
  selectedTargetChange(host, "metrics", { span });
  range.addEventListener("change", () => navigate(locationFor("metrics", { id: target.id, span: range.value })));
  const metricsPath = `/hosts/${key(target.id)}/metrics`;
  const [page, settings] = await Promise.all([
    get(metricsPath + params({ from, to, limit: 200 })), get("/sampling-settings").catch(() => null),
  ]);
  updateSnapshotTime(lastSuccess, page, target.last_success_at);
  const bucketWidth = Math.ceil(span / 600);
  const maxGap = Number.isFinite(settings?.host_interval) && settings.host_interval > 0
    ? Math.ceil(settings.host_interval * 2000 / bucketWidth) * bucketWidth : Infinity;
  const rows = snapshotItems(page);
  let cursor = page.next_cursor;
  while (cursor) {
    const next = await get(metricsPath + params({ from, to, limit: 200, cursor }));
    if (generation !== id) return;
    rows.push(...snapshotItems(next));
    if (next.next_cursor === cursor) break;
    cursor = next.next_cursor;
  }
  const history = Array.isArray(page.history) ? page.history : [];
  const cpu = rows.find((row) => row.object_key === "cpu" || row.metric === "cpu_percent");
  const memory = rows.find((row) => row.object_key === "memory" || row.metric === "memory_percent");
  const traces = {
    cpu: ["cpu_percent", "cpu_usage_percent"], memory: ["memory_percent", "memory_usage_percent"],
    disk: ["disk_percent", "disk_usage_percent"], rx: ["rx_bytes_per_second", "network_receive_bytes_per_second"],
    tx: ["tx_bytes_per_second", "network_transmit_bytes_per_second"],
  };
  const series = (kind, dimension, max, label) => sparkline(history.filter((point) =>
    traces[kind].includes(point.metric) && (!dimension || point.dimension === dimension)),
  from, to, max, label, maxGap);
  const cards = element("div", { class: "metric-cards" },
    [["CPU", "cpu", cpu?.cpu_percent ?? cpu?.usage_percent], ["内存", "memory", memory?.memory_percent ?? memory?.usage_percent]]
      .map(([label, metric, value]) => element("div", { class: "metric-card" },
        element("h2", {}, label), element("p", { class: "metric-number" }, formatPercent(value)), series(metric, "", 100, label + "趋势"))));
  const disks = rows.filter((row) => row.mountpoint).map((row) => [
    row.mountpoint, usageCell({ ...row, percent: row.disk_percent ?? row.usage_percent }),
    series("disk", row.mountpoint, 100, "磁盘使用率趋势"),
    button("创建告警", () => ruleEditor({
      selector: { target_id: target.id, metric: "disk_usage_percent", mountpoint: row.mountpoint },
    })),
  ]);
  const nics = rows.filter((row) => row.interface).map((row) => [
    row.interface, element("span", { class: "metric-rates" },
      element("span", {}, `接收 ${formatBytes(row.rx_bytes_per_second, true)}`),
      element("span", {}, `发送 ${formatBytes(row.tx_bytes_per_second, true)}`)),
    series("rx", row.interface, undefined, "接收速率趋势"), series("tx", row.interface, undefined, "发送速率趋势"),
  ]);
  const diskList = listTable("磁盘", ["挂载点", "已用 / 总量", "趋势", "操作"], disks, snapshotEmpty(page, "没有本地磁盘挂载点"));
  const networkList = listTable("网卡", ["接口", "接收 / 发送速率", "接收趋势", "发送趋势"], nics, snapshotEmpty(page, "没有网卡数据"));
  const oldLists = !content.inert && content.querySelectorAll(".metric-inventories .inventory");
  const scroll = oldLists && Array.from(oldLists, (node) => ({ left: node.scrollLeft, top: node.scrollTop }));
  insert(id, heading("主机详情", [link("主机管理", locationFor("targets"), "secondary"),
    link("网络详情", locationFor("network", { id: target.id }), "secondary")], true, { picker: host, lastSuccess }),
  element("div", { class: "toolbar" }, control("时间范围", range), firewallAuthorizationInfo(target)), cards,
  element("div", { class: "metric-inventories" },
    element("section", {}, element("h2", {}, "磁盘"), diskList),
    element("section", {}, element("h2", {}, "网卡"), networkList)));
  if (scroll?.length === 2) {
    diskList.scrollTo(scroll[0]);
    networkList.scrollTo(scroll[1]);
  }
  mountCollection(id, { view: "host_metrics", target_id: target.id }, () => render({ quiet: true }));
}

function getNetworkRows(group, rows) {
  if (group === "interfaces") return rows.map((r) => [
    r.name || r.ifname, r.state || r.operstate,
    (r.addresses || r.addr_info || []).map((a) => typeof a === "string" ? a : [a.local || a.address, a.prefixlen].filter((v) => v != null).join("/")),
    r.mtu,
  ]);
  if (group === "routes") return rows.map((r) => [
    r.table, r.destination || r.dst || r.prefix, r.gateway || r.next_hop || r.next_hops,
    r.interface || r.dev, r.metric,
  ]);
  if (group === "listeners") return rows.map((r) => [
    r.protocol?.toUpperCase(), r.address, r.port, r.process || (r.process_state === "unreadable" ? "不可读（端口已采集）" : display(r.process_state)),
  ]);
  return rows.flatMap(firewallRows);
}

function firewallState(backend, state, detail = "") {
  return [[backend, null, null, detail, chip(state)]];
}

function nftRows(backend, payload) {
  if (!Array.isArray(payload?.nftables)) return firewallState(backend, "unreadable");
  const rows = [];
  const actionKeys = new Set(["accept", "drop", "reject", "return", "jump", "goto", "queue", "continue",
    "dnat", "snat", "masquerade", "redirect", "log", "notrack", "tproxy", "fwd", "dup"]);
  for (const item of payload.nftables) {
    if (item.chain?.policy) {
      const { family, table, name, policy } = item.chain;
      rows.push([backend, [family, table].filter(Boolean).join(" / "), name, "默认策略", policy]);
    }
    if (!item.rule) continue;
    const { family, table, chain, expr, comment } = item.rule;
    const matches = [];
    const verdicts = [];
    for (const expression of Array.isArray(expr) ? expr : []) {
      const keys = Object.keys(expression ?? {});
      const kind = keys[0];
      if (keys.length === 1 && actionKeys.has(kind)) {
        const value = expression[kind];
        verdicts.push(value == null ? kind : `${kind} ${value.target || display(value)}`);
      } else matches.push(display(expression));
    }
    if (comment) matches.push(comment);
    rows.push([backend, [family, table].filter(Boolean).join(" / "), chain, matches, verdicts]);
  }
  return rows.length ? rows : firewallState(backend, "no_rules");
}

function ufwRows(backend, payload) {
  if (typeof payload !== "string") return firewallState(backend, "unreadable");
  if (/^Status:\s+inactive\s*$/im.test(payload)) return firewallState(backend, "inactive");
  if (!/^Status:\s+active\s*$/im.test(payload)) return firewallState(backend, "unreadable");
  const rows = [];
  let inRules = false;
  let hasRule = false;
  for (const raw of payload.split(/\r?\n/)) {
    const line = raw.trim();
    if (line.startsWith("Default:")) rows.push([backend, null, null, "默认策略", line.slice(8).trim()]);
    if (/^To\s{2,}Action\s{2,}From$/.test(line)) {
      inRules = true;
      continue;
    }
    if (!inRules || !line || /^[-\s]+$/.test(line)) continue;
    const [destination, action, ...source] = line.split(/\s{2,}/);
    if (action && source.length) rows.push([backend, null, null, `${source.join(" ")} → ${destination}`, action]);
    else rows.push([backend, null, null, line, null]);
    hasRule = true;
  }
  return hasRule ? rows : [...rows, ...firewallState(backend, "no_rules")];
}

function legacyRows(backend, entry) {
  if (entry?.status !== "ok" || typeof entry.payload !== "string") {
    return firewallState(backend, entry?.status === "ok" || entry?.status === "failed" ? "unreadable" : entry?.status || "unreadable",
      sourceErrorLabel(entry?.error_code));
  }
  const rows = [];
  let table;
  for (const raw of entry.payload.split(/\r?\n/)) {
    const line = raw.trim();
    if (line.startsWith("*")) table = line.slice(1);
    if (line.startsWith(":")) {
      const [chain, policy] = line.slice(1).split(/\s+/, 2);
      if (chain && policy && policy !== "-") rows.push([backend, table, chain, "默认策略", policy]);
    }
    if (!line.startsWith("-A ")) continue;
    const [, chain, ...parts] = line.match(/(?:[^\s"'\\]|\\.|"(?:[^"\\]|\\.)*"|'[^']*')+/g) || [];
    const jump = parts.findIndex((part) => ["-j", "--jump", "-g", "--goto"].includes(part));
    const action = jump >= 0 ? parts.splice(jump, 2).join(" ") : null;
    rows.push([backend, table, chain, parts.join(" "), action]);
  }
  return rows.length ? rows : firewallState(backend, "no_rules");
}

function firewallRows(record) {
  const backend = record.backend || record.name;
  if (record.format === "families" && record.payload) {
    return ["ipv4", "ipv6"].flatMap((family) => legacyRows(`${backend} · ${family.toUpperCase()}`, record.payload[family]));
  }
  if (record.status !== "ok") {
    return firewallState(backend, record.status === "failed" ? "unreadable" : record.status, sourceErrorLabel(record.error_code));
  }
  if (backend === "nftables") return nftRows(backend, record.payload);
  if (backend === "ufw") return ufwRows(backend, record.payload);
  return firewallState(backend, "unsupported");
}

async function showNetwork(query, id) {
  const [targets, target] = await detailTargets(false, query);
  if (id !== generation) return;
  const requested = query.get("tab");
  const group = Object.hasOwn(networkTabs, requested) ? requested : "interfaces";
  if (!target) {
    const host = targets.length ? targetContext(targets, null) : null;
    if (host) selectedTargetChange(host, "network", { tab: group });
    insert(id, heading("网络", [], false, host && { picker: host }),
      notice(query.get("id") ? "此主机已解绑或不存在。" : "尚未绑定 Linux 主机。"),
      null);
    return;
  }
  bindDefaultTarget("network", query, target);
  const headers = {
    interfaces: ["名称", "链路", "地址 / 前缀", "MTU"],
    routes: ["路由表", "目的前缀", "下一跳", "出接口", "优先级"],
    listeners: ["协议", "绑定地址", "端口", "进程"],
    firewall: ["后端", "表", "链", "匹配条件", "动作 / 状态"],
  };
  const host = targetContext(targets, target);
  const lastSuccess = snapshotContext();
  selectedTargetChange(host, "network", { tab: group });
  const listing = pageList(`/hosts/${key(target.id)}/network/${group}`, {}, (page) => {
    updateSnapshotTime(lastSuccess, page, target.last_success_at);
    const rows = snapshotItems(page);
    return [listTable(networkTabs[group], headers[group], getNetworkRows(group, rows), snapshotEmpty(page, "采集成功，未发现数据")),
      group === "listeners" && rows.some((row) => !row.process && row.process_state === "unreadable")
        ? meta("部分端口的进程不可读。可查看下方的主机授权状态。内核套接字等可能没有可显示的进程。") : null,
      ["firewall", "listeners"].includes(group) ? firewallAuthorizationInfo(target, true) : null].filter(Boolean);
  });
  insert(id, heading("网络", [link("主机详情", detailsFor(target), "secondary")], true, { picker: host, lastSuccess }),
    element("div", { class: "toolbar" }, meta("只读")),
    tabs(Object.entries(networkTabs).map(([tab, label]) => [tab, label, locationFor("network", { id: target.id, tab })]), group),
    listing);
  mountCollection(id, { view: "network", target_id: target.id, group }, listing.refreshSnapshot, listing.snapshotReady);
}

function clusterObjectButton(target, row, metric) {
  const uid = row.uid || row.object_key;
  return button("创建告警", () => ruleEditor({ selector: {
    target_id: target.id, metric, uid, namespace: row.namespace, name: row.name,
  } }), "secondary", { disabled: !uid });
}

function clusterName(value) {
  return element("strong", { class: "cluster-name" }, value);
}

function clusterNamespace(value) {
  return element("span", { class: "cluster-namespace" }, display(value));
}

async function showCluster(query, id) {
  const [targets, target] = await detailTargets(true, query);
  if (id !== generation) return;
  if (!target) {
    insert(id, heading("集群详情"), notice("请选择仍绑定的集群。"),
      link("主机管理", locationFor("targets", { tab: "clusters" }), "secondary"));
    return;
  }
  bindDefaultTarget("cluster", query, target);
  const chosen = query.get("tab");
  const tab = Object.hasOwn(clusterTabs, chosen) ? chosen : "namespaces";
  const namespace = tab !== "nodes" ? query.get("namespace") || "" : "";
  const path = `/clusters/${key(target.id)}/resources/`;
  const cluster = targetContext(targets, target, "选择集群");
  selectedTargetChange(cluster, "cluster", { tab });
  const status = target.connection_status || target.status || "pending";
  const lastSuccess = snapshotContext();
  updateSnapshotTime(lastSuccess, {}, target.last_success_at);
  const filter = element("div", { class: "toolbar" }, chip(status));
  if (["deployments", "pods", "services"].includes(tab)) {
    const namespaces = snapshotItems(await allPages(path + "namespaces"));
    const options = namespaces.map((row) => [row.name, row.name]);
    if (namespace && !options.some(([name]) => name === namespace)) options.push([namespace, namespace]);
    const names = select("namespace", [["", "全部"], ...options], namespace);
    names.addEventListener("change", () => navigate(locationFor("cluster", { id: target.id, tab, namespace: names.value })));
    filter.append(control("命名空间", names));
  }
  const columns = {
    namespaces: ["命名空间", "状态", "部署", "Pod", "服务"],
    deployments: ["名称", "命名空间", "就绪 / 期望副本", "操作"],
    pods: ["名称", "命名空间", "阶段", "就绪", "所在节点", "操作"],
    services: ["名称", "命名空间", "类型", "端口", "就绪后端数"],
    nodes: ["名称", "Ready", "关联主机", "操作"],
  };
  const listing = pageList(path + tab, { namespace }, (page) => {
    const data = snapshotItems(page);
    const rows = data.map((r) => {
      switch (tab) {
        case "namespaces":
          return [clusterName(link(r.name, locationFor("cluster", { id: target.id, tab: "deployments", namespace: r.name }))),
            r.phase ?? r.state ?? r.status, r.deployment_count ?? r.deployments, r.pod_count ?? r.pods, r.service_count ?? r.services];
        case "deployments":
          return [clusterName(r.name), clusterNamespace(r.namespace), `${display(r.ready ?? r.ready_replicas)} / ${display(r.desired ?? r.desired_replicas)}`,
            clusterObjectButton(target, r, "deployment_state")];
        case "pods":
          return [clusterName(r.name), clusterNamespace(r.namespace), r.phase, r.ready, r.node_name ?? r.node, clusterObjectButton(target, r, "pod_ready")];
        case "services":
          return [clusterName(r.name), clusterNamespace(r.namespace), r.type, (r.ports || []).map((p) => typeof p === "object" ? [p.port, p.protocol].filter(Boolean).join("/") : p),
            r.ready_backends ?? r.ready_endpoints];
        default:
          return [clusterName(r.name), r.ready, r.host_name ?? r.linked_host_name ?? r.host_id, clusterObjectButton(target, r, "node_ready")];
      }
    });
    updateSnapshotTime(lastSuccess, page, target.last_success_at);
    return [listTable(clusterTabs[tab], columns[tab], rows,
      snapshotEmpty(page, namespace ? "未找到匹配项" : "采集成功，未发现数据"))].filter(Boolean);
  });
  insert(id, heading("集群详情", [link("主机管理", locationFor("targets", { tab: "clusters" }), "secondary")], true,
    { picker: cluster, lastSuccess }),
    filter, tabs(Object.entries(clusterTabs).map(([name, label]) => [name, label,
      locationFor("cluster", { id: target.id, tab: name, namespace: ["nodes", "namespaces"].includes(name) ? "" : namespace }),
    ]), tab), listing);
  mountCollection(id, { view: "cluster", target_id: target.id, group: tab }, listing.refreshSnapshot, listing.snapshotReady);
}

const metrics = {
  target_reachable: { label: "采集连接", kind: "", value: "bool", on: "可达", off: "失联" },
  cpu_usage_percent: { label: "CPU 使用率", kind: "host", unit: "%" },
  memory_usage_percent: { label: "内存使用率", kind: "host", unit: "%" },
  disk_usage_percent: { label: "磁盘使用率", kind: "host", field: "mountpoint", unit: "%" },
  disk_capacity_bytes: { label: "磁盘容量", kind: "host", field: "mountpoint", unit: "字节" },
  disk_available_bytes: { label: "磁盘可用容量", kind: "host", field: "mountpoint", unit: "字节" },
  network_receive_bytes_per_second: { label: "网卡接收速率", kind: "host", field: "interface", unit: "字节 / 秒" },
  network_transmit_bytes_per_second: { label: "网卡发送速率", kind: "host", field: "interface", unit: "字节 / 秒" },
  systemd_state: { label: "systemd 服务状态", kind: "host", field: "unit", value: "state" },
  port_listening: { label: "端口", kind: "host", field: "listener", value: "bool", on: "正在监听", off: "未监听" },
  node_ready: { label: "节点 Ready", kind: "cluster", field: "uid", group: "nodes", value: "bool", on: "就绪", off: "未就绪" },
  deployment_state: { label: "Deployment 状态", kind: "cluster", field: "uid", group: "deployments", value: "state" },
  deployment_replica_gap: { label: "Deployment 副本缺口", kind: "cluster", field: "uid", group: "deployments", unit: "副本" },
  pod_phase: { label: "Pod 阶段", kind: "cluster", field: "uid", group: "pods", value: "phase" },
  pod_ready: { label: "Pod Ready", kind: "cluster", field: "uid", group: "pods", value: "bool", on: "就绪", off: "未就绪" },
};
const operators = { eq: "等于", ne: "不等于", gt: "大于", gte: "大于等于", lt: "小于", lte: "小于等于" };
const eventFilters = { all: "全部", active: "活动", recovered: "已恢复", unread: "未读" };
const deliveryText = {
  delivered: "已投递", accepted: "已受理", failed: "失败", unknown: "结果未知",
  disabled: "未启用", not_selected: "规则未选中", not_enabled: "未启用", not_configured: "未配置",
  queued: "排队", sending: "发送中", retrying: "等待重试", pending: "待投递",
};

function conditionValue(metric, value) {
  const spec = metrics[metric] || {};
  if (spec.value === "bool" && typeof value === "boolean") return value ? spec.on : spec.off;
  if (spec.value === "state" && statusText[value]) return statusText[value];
  return `${display(value)}${typeof value === "number" && spec.unit ? " " + spec.unit : ""}`;
}

function conditionLabel(selector, condition) {
  if (!selector || !condition) return "—";
  return [metrics[selector.metric]?.label, operators[condition.op] || condition.op, conditionValue(selector.metric, condition.value)].filter(Boolean).join(" ");
}

function selectorLabel(selector) {
  if (!selector) return "—";
  return selector.mountpoint || selector.interface || selector.unit
    || (selector.port ? `${selector.protocol?.toUpperCase()} ${selector.address}:${selector.port}` : "")
    || [selector.namespace, selector.name].filter(Boolean).join(" / ") || selector.uid || "—";
}

function ruleTrigger(trigger = {}) {
  if (Number.isInteger(trigger.duration_seconds)) return `持续 ${trigger.duration_seconds} 秒`;
  if (Number.isInteger(trigger.consecutive_samples)) return `连续 ${trigger.consecutive_samples} 次`;
  return "—";
}

function eventRow(event, filter) {
  const seen = event.panel_read_revision ?? 0;
  const revision = event.panel_revision ?? 0;
  return [revision ? chip(seen < revision ? "active" : "recovered", seen < revision ? "未读" : "已读") : "—",
    severityText[event.severity] || event.severity, event.source === "collection" ? `采集异常 · ${groupLabel(event.group)}` : event.rule_name,
    [...new Set([event.target_name, event.object_name].filter(Boolean))].join(" / "), chip(event.status),
    formatTime(event.triggered_at), formatTime(event.recovered_at),
    link("查看", locationFor("event", { id: event.id, filter }), "secondary")];
}

async function showAlerts(query, id) {
  const section = ["rules", "channels"].includes(query.get("tab")) ? query.get("tab") : "events";
  const header = heading("告警", [button("新建规则", () => ruleEditor(), "primary")]);
  const menu = tabs([["events", "事件", locationFor("alerts")],
    ["rules", "规则", locationFor("alerts", { tab: "rules" })],
    ["channels", "通知渠道", locationFor("alerts", { tab: "channels" })]], section);
  if (section === "channels") {
    insert(id, header, menu, await channelSettings());
    refreshUnread();
    return;
  }
  if (section === "rules") {
    const [targets, settings] = await Promise.all([allPages("/targets"), get("/sampling-settings")]);
    const name = new Map(targets.map((target) => [target.id, target.name]));
    const listing = pageList("/alert-rules", {}, (page) => [
      listTable("告警规则", ["规则", "监控对象", "条件", "状态", "通知渠道", "操作"], items(page).map((rule) => [
        rule.name, element("div", {}, name.get(rule.selector?.target_id) || "源已解绑",
          meta(selectorLabel(rule.selector))),
        element("div", {}, conditionLabel(rule.selector, rule.condition), meta(ruleTrigger(rule.trigger))),
        element("div", {}, chip(rule.enabled ? "success" : "inactive", rule.enabled ? "已启用" : "已停用"),
          rule.enabled && !settings.poll_enabled && rule.trigger?.duration_seconds > 0 ? meta("需开启轮询") : null),
        Object.entries(rule.channels || {}).filter(([, enabled]) => enabled).map(([channel]) => channelText[channel]),
        element("div", { class: "actions" }, button("编辑", () => ruleEditor({ rule })),
          button(rule.enabled ? "停用" : "启用", async (event) => {
            const trigger = event.currentTarget;
            trigger.disabled = true;
            try {
              await api(`/alert-rules/${key(rule.id)}`, "PATCH", { enabled: !rule.enabled, revision: rule.revision });
              notify(rule.enabled ? "已停用规则。" : "已启用规则。");
              render();
            } catch (error) {
              notify(error.message);
              trigger.disabled = false;
            }
          })),
      ]), "暂无告警规则"),
    ]);
    insert(id, header, menu, listing);
    refreshUnread();
    return;
  }
  const selected = query.get("filter");
  const filter = Object.hasOwn(eventFilters, selected) ? selected : "all";
  const listing = pageList("/alert-events", {
    status: filter === "active" || filter === "recovered" ? filter : "",
    unread: filter === "unread",
  }, (page) => {
    if (id === generation) setUnread(page.unread_count);
    return [listTable("告警事件", ["面板", "级别", "告警规则", "对象", "状态", "触发", "恢复", "操作"],
      items(page).map((event) => eventRow(event, filter)), "暂无符合条件的事件")];
  });
  insert(id, header, menu, tabs(Object.entries(eventFilters).map(([name, label]) =>
    [name, label, locationFor("alerts", { filter: name === "all" ? "" : name })]), filter), listing);
}

function eventSource(event, target) {
  const selector = event.selector || {};
  const spec = metrics[selector.metric] || {};
  if (!target || !event.source_available) return null;
  if (event.source === "collection") {
    if (event.group === "systemd" || event.group === "deployments") {
      return locationFor("services", { source: isCluster(target) ? "cluster" : "host", target: target.id });
    }
    if (!isCluster(target) && Object.hasOwn(networkTabs, event.group)) return locationFor("network", { id: target.id, tab: event.group });
    if (isCluster(target) && Object.hasOwn(clusterTabs, event.group)) return locationFor("cluster", { id: target.id, tab: event.group });
    return detailsFor(target);
  }
  if (selector.metric === "target_reachable") return detailsFor(target);
  if (selector.metric === "port_listening") return locationFor("network", { id: target.id, tab: "listeners" });
  if (selector.metric === "systemd_state" || selector.metric === "deployment_state") {
    return locationFor("services", { source: isCluster(target) ? "cluster" : "host",
      target: target.id, q: selector.unit || selector.name || event.object_name, namespace: selector.namespace });
  }
  if (isCluster(target)) return locationFor("cluster", { id: target.id, tab: spec.group, namespace: selector.namespace });
  return locationFor("metrics", { id: target.id });
}

async function showEvent(query, id) {
  const eventID = query.get("id");
  if (!eventID) throw new Error("缺少事件编号。");
  const path = `/alert-events/${key(eventID)}`;
  const event = await get(path);
  if (id !== generation) return;
  const error = notice("");
  const filter = query.get("filter");
  const back = locationFor("alerts", { filter: Object.hasOwn(eventFilters, filter) && filter !== "all" ? filter : "" });
  const deliveries = items(event.deliveries).map((entry) => [
    entry.phase === "trigger" ? "触发" : ["recover", "recovery"].includes(entry.phase) ? "恢复" : entry.phase,
    channelText[entry.channel] || entry.channel, deliveryText[entry.status] || entry.status,
    entry.address, entry.detail, formatTime(entry.updated_at),
  ]);
  const sourceBox = element("div", { class: "actions" });
  const details = event.source === "collection" ? [
    ["类型", "采集异常"], ["级别", severityText[event.severity] || event.severity],
    ["目标", event.target_name], ["采集环节", groupLabel(event.group)], ["类别", sourceErrorLabel(event.error_category || "")],
    ["处理状态", chip(event.status)], ["首次观察", formatTime(event.triggered_at)], ["最后观察", formatTime(event.observed_at)],
    ["恢复时间", formatTime(event.recovered_at)],
  ] : [
    ["规则", event.rule_name], ["级别", severityText[event.severity] || event.severity],
    ["对象", [...new Set([event.target_name, event.object_name].filter(Boolean))].join(" / ")], ["状态", chip(event.status)],
    ["触发条件", conditionLabel(event.selector, event.condition)], ["连续条件", ruleTrigger(event.trigger)],
    ["最新值", conditionValue(event.selector?.metric, event.latest_value)], ["观察时间", formatTime(event.observed_at)],
    ["触发时间", formatTime(event.triggered_at)], ["恢复时间", formatTime(event.recovered_at)],
    ["数据来源", [metrics[event.selector?.metric]?.label, selectorLabel(event.selector)].filter(Boolean).join(" / ")],
    ...(event.detail_state && event.detail_state !== "ok" ? [["数据状态", ["unevaluable", "unknown", "object_missing"].includes(event.detail_state) ? "暂不可评估" : statusText[event.detail_state] || event.detail_state]] : []),
  ];
  const body = element("div", { class: "list-page list-details" }, pairs(details), sourceBox, error, element("h2", {}, "投递结果"),
  listTable("投递结果", ["阶段", "渠道", "结果", "目标", "详情", "更新时间"], deliveries, "暂无投递结果"));
  insert(id, heading("事件详情", [link("返回事件列表", back, "secondary")]), body);
  if (event.source_available) {
    allPages("/targets").then((targets) => {
      const source = eventSource(event, targets.find((entry) => entry.id === event.target_id));
      sourceBox.replaceChildren(source ? link("回到数据来源", source, "secondary") : meta("数据来源已不可用"));
    }).catch(() => { sourceBox.textContent = "暂时读不到数据来源。"; });
  } else sourceBox.textContent = "数据来源已不可用。";
  const revision = event.panel_revision;
  if (Number.isInteger(revision) && revision > event.panel_read_revision) {
    const markRead = async () => {
      const request = readCapture();
      try {
        const result = await api(path + "/read", "POST", { through_revision: revision });
        setUnread(result?.unread_count, request);
        formError(error, null);
      } catch (failure) {
        formError(error, failure);
        error.append(button("重试标为已读", markRead));
      }
    };
    await markRead();
  } else refreshUnread();
}

async function ruleEditor({ rule, selector: initial, objectTitle = "" } = {}) {
  const state = element("div", { class: "stack" }, notice("正在读取监控对象和通知目标…"), button("关闭", closeDialog));
  showDialog(rule ? "编辑告警规则" : "创建告警规则", state);
  try {
    const [targets, destinations, settings] = await Promise.all([
      allPages("/targets"), allPages("/notification-targets"), get("/sampling-settings"),
    ]);
    if (!state.isConnected || !dialog.open) return;
    if (!targets.length) {
      state.replaceChildren(notice("先绑定 Linux 主机或 Kubernetes 集群。"),
        link("主机管理", locationFor("targets"), "secondary"), button("关闭", closeDialog));
      return;
    }
    const selected = rule?.selector || initial || {};
    const editingUnavailable = Boolean(rule) && !targets.some((target) => target.id === selected.target_id);
    const name = input("name", rule?.name ?? (objectTitle ? `${objectTitle}告警` : ""), { required: true, maxlength: 160 });
    const targetOptions = targets.map((target) => [target.id, `${target.name} · ${isCluster(target) ? "集群" : "主机"}`]);
    if (editingUnavailable) targetOptions.unshift([selected.target_id, "原监控目标已解绑"]);
    const target = select("target_id", targetOptions, selected.target_id);
    const metric = select("metric", [], selected.metric);
    const level = select("severity", Object.entries(severityText), rule?.severity || "warning");
    const enabled = checkbox("enabled", rule?.enabled ?? true);
    const mode = select("trigger_mode", [["consecutive_samples", "连续采样次数"], ["duration_seconds", "持续秒数"]],
      Number.isInteger(rule?.trigger?.duration_seconds) ? "duration_seconds" : "consecutive_samples");
    const threshold = input("trigger_value", rule?.trigger?.consecutive_samples ?? rule?.trigger?.duration_seconds ?? 1,
      { required: true, type: "number", min: 1, max: 1000000 });
    const requiresPolling = notice("");
    const updateTrigger = () => {
      const time = mode.value === "duration_seconds";
      threshold.min = time ? 0 : 1;
      threshold.max = time ? 31536000 : 1000000;
      requiresPolling.textContent = !settings.poll_enabled && time && Number(threshold.value) > 0
        ? "非零持续时间规则需开启轮询才会触发。" : "";
    };
    mode.addEventListener("change", updateTrigger);
    threshold.addEventListener("input", updateTrigger);
    updateTrigger();
    const subject = element("div", { class: "fields wide" });
    const comparator = element("div", { class: "fields wide" });
    const loadState = notice("");
    const error = notice("");
    const save = submit();
    let selectorExtras = () => ({});
    let readCondition = () => ({});
    let selectionGeneration = 0;
    function optionsForTarget(preferred) {
      const current = targets.find((entry) => entry.id === target.value);
      const kind = isCluster(current) ? "cluster" : "host";
      const choices = Object.entries(metrics).filter(([id, entry]) => !entry.kind || entry.kind === kind || !current && id === preferred)
        .map(([id, entry]) => [id, entry.label]);
      metric.replaceChildren(...choices.map(([id, label]) => element("option", { value: id }, label)));
      metric.value = choices.some(([id]) => id === preferred) ? preferred : choices[0][0];
    }
    async function updateMetric(prefill = {}, initialCondition) {
      const own = ++selectionGeneration;
      const chosen = metrics[metric.value];
      const current = targets.find((entry) => entry.id === target.value);
      subject.replaceChildren();
      formError(loadState, null);
      save.disabled = !current;
      if (!current) loadState.textContent = "请为此规则选择仍绑定的目标。";
      selectorExtras = () => ({});
      const operatorsFor = chosen.value ? ["eq", "ne"] : ["gt", "gte", "lt", "lte", "eq", "ne"];
      const op = select("op", operatorsFor.map((id) => [id, operators[id]]), initialCondition?.op);
      let values;
      let typed = (value) => value;
      if (chosen.value === "bool") {
        values = select("value", [["false", chosen.off], ["true", chosen.on]], initialCondition?.value);
        typed = (value) => value === "true";
      } else if (chosen.value === "state") {
        const states = ["failed", "running", "stopped", "starting"];
        values = select("value", states.map((value) => [value, statusText[value]]), initialCondition?.value);
      } else if (chosen.value === "phase") {
        values = select("value", ["Failed", "Pending", "Running", "Succeeded", "Unknown"].map((value) => [value, value]), initialCondition?.value);
      } else {
        values = input("value", initialCondition?.value ?? (metric.value.endsWith("percent") ? 90 : ""), { type: "number", step: "any", required: true });
        typed = Number;
      }
      comparator.replaceChildren(control("条件", op), control(chosen.unit ? `阈值（${chosen.unit}）` : "状态", values));
      readCondition = () => ({ op: op.value, value: typed(values.value) });
      const valuesFor = Object.fromEntries(Object.entries(prefill).filter(([, value]) => value !== undefined));
      if (chosen.field === "listener") {
        const protocol = select("protocol", [["tcp", "TCP"], ["udp", "UDP"]], valuesFor.protocol);
        const family = select("family", [["ipv4", "IPv4"], ["ipv6", "IPv6"]], valuesFor.family);
        const address = input("address", valuesFor.address, { required: true, placeholder: "IP 地址或 *（通配）" });
        const port = input("port", valuesFor.port, { type: "number", min: 1, max: 65535, required: true });
        subject.append(control("协议", protocol), control("地址族", family), control("绑定地址", address), control("端口", port));
        selectorExtras = () => ({ protocol: protocol.value, family: family.value, address: address.value.trim(), port: Number(port.value) });
      } else if (chosen.field && current) {
        const field = chosen.field;
        const fieldLabels = { unit: "systemd 服务", uid: clusterTabs[chosen.group], mountpoint: "磁盘挂载点", interface: "网卡" };
        loadState.textContent = "正在读取已采集对象…";
        save.disabled = true;
        try {
          let entries;
          if (field === "uid") {
            entries = snapshotItems(await allPages(`/clusters/${key(current.id)}/resources/${chosen.group}`));
          } else if (field === "unit") {
            entries = await allPages("/services", { host_id: current.id });
          } else {
            entries = snapshotItems(await allPages(`/hosts/${key(current.id)}/metrics`));
          }
          if (own !== selectionGeneration) return;
          const byID = new Map();
          for (const entry of entries) {
            const id = field === "uid" ? entry.uid || entry.object_key : entry[field] || (field === "unit" ? entry.name : "");
            if (id) byID.set(id, entry);
          }
          if (valuesFor[field] && !byID.has(valuesFor[field])) {
            byID.set(valuesFor[field], { ...valuesFor, name: `${valuesFor.name || valuesFor[field]}（原对象）` });
          }
          const options = [...byID].map(([id, entry]) => [id, field === "uid"
            ? [entry.namespace, entry.name || id].filter(Boolean).join(" / ") : id]);
          const object = select(field, [["", "选择监控对象"], ...options], valuesFor[field]);
          object.required = true;
          subject.append(control(fieldLabels[field], object, true));
          selectorExtras = () => {
            const entry = byID.get(object.value);
            return { [field]: object.value, ...(field === "uid" ? { namespace: entry?.namespace, name: entry?.name } : {}) };
          };
          save.disabled = !options.length;
          loadState.textContent = options.length ? "" : "没有已采集对象，请采集后重试。";
        } catch (failure) {
          if (own === selectionGeneration) formError(loadState, failure);
        }
      }
    }
    optionsForTarget(selected.metric);
    const byChannel = new Map();
    const checks = element("fieldset", { class: "checks" }, element("legend", {}, "通知渠道"));
    const destinationsBox = element("div", { class: "stack" });
    for (const [channel, label] of Object.entries(channelText)) {
      const check = checkbox(channel, rule?.channels?.[channel] ?? channel === "panel");
      const area = element("div", { class: "stack" });
      let destinationChecks = [];
      checks.append(element("label", {}, check, label));
      if (channel !== "panel") {
        const selectedIDs = new Set(rule?.notification_target_ids?.[channel] || []);
        destinationChecks = destinations.filter((destination) => destination.channel === channel).map((destination) => {
          const choice = checkbox(`${channel}_target`, selectedIDs.has(destination.id));
          choice.value = destination.id;
          return { choice, item: destination };
        });
        const list = element("fieldset", { class: "checks" }, element("legend", {}, `${label}通知目标`),
          destinationChecks.map(({ choice, item }) => element("label", {}, choice, item.name)));
        area.append(destinationChecks.length ? list : meta(`请先在通知渠道中添加${label}目标。`));
      }
      area.hidden = !check.checked || channel === "panel";
      check.addEventListener("change", () => { area.hidden = !check.checked || channel === "panel"; });
      destinationsBox.append(area);
      byChannel.set(channel, { check, destinationChecks });
    }
    const selection = () => ({
      channels: Object.fromEntries([...byChannel].map(([channel, value]) => [channel, value.check.checked])),
      notification_target_ids: Object.fromEntries([...byChannel].filter(([channel]) => channel !== "panel")
        .map(([channel, value]) => [channel, value.destinationChecks.filter(({ choice }) => choice.checked).map(({ choice }) => choice.value)])),
    });
    const test = button("测试通知", async () => {
      test.disabled = true;
      try {
        const config = selection();
        const targets = [...byChannel].flatMap(([channel, entry]) => config.channels[channel] && channel !== "panel"
          ? entry.destinationChecks.filter(({ choice }) => choice.checked).map(({ item }) => item) : []);
        const checks = await Promise.all([
          ...(config.channels.panel ? [testChannel(null)] : []), ...targets.map(testChannel),
        ]);
        if (!checks.length) throw new Error("请选择至少一个通知渠道和相应目标。");
        error.classList.remove("error");
        error.textContent = checks.join(" · ");
      } catch (failure) {
        formError(error, failure);
      } finally {
        test.disabled = false;
      }
    });
    const form = element("form", { class: "stack" },
      element("div", { class: "fields" }, control("规则名称", name, true), control("监控目标", target), control("监控项", metric),
        subject, comparator, control("触发方式", mode), control("门槛", threshold), control("级别", level),
        element("label", { class: "checks" }, enabled, "启用规则")),
      requiresPolling, loadState, checks, destinationsBox, error,
      element("div", { class: "form-actions" }, button("取消", closeDialog), test, save));
    target.addEventListener("change", () => {
      const previous = metric.value;
      optionsForTarget(previous);
      updateMetric();
    });
    metric.addEventListener("change", () => updateMetric());
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const notifyConfig = selection();
      for (const channel of ["telegram", "email"]) {
        if (notifyConfig.channels[channel] && !notifyConfig.notification_target_ids[channel].length) {
          formError(error, `请选择${channelText[channel]}通知目标。`);
          return;
        }
      }
      const document = { name: name.value.trim(), severity: level.value, enabled: enabled.checked,
        selector: { target_id: target.value, metric: metric.value, ...selectorExtras() },
        condition: readCondition(), trigger: { [mode.value]: Number(threshold.value) }, ...notifyConfig };
      if (rule) document.revision = rule.revision;
      save.disabled = true;
      try {
        await api(rule ? `/alert-rules/${key(rule.id)}` : "/alert-rules", rule ? "PATCH" : "POST", document);
        closeDialog();
        notify("已保存告警规则。");
        navigate(locationFor("alerts", { tab: "rules" }));
      } catch (failure) {
        formError(error, failure);
        save.disabled = false;
      }
    });
    state.replaceChildren(form);
    updateMetric(selected, rule?.condition);
  } catch (failure) {
    state.replaceChildren(notice(failure.message, true), button("关闭", closeDialog));
  }
}

async function testChannel(destination) {
  const path = destination ? `/notification-targets/${key(destination.id)}/test` : "/notification-settings/panel/test";
  const result = await api(path, "POST", {});
  const details = items(result?.deliveries).map((entry) =>
    [entry.address, deliveryText[entry.status] || entry.status, entry.detail].filter(Boolean).join(" "));
  return `${destination?.name || "面板通知"}：${deliveryText[result?.result] || statusText[result?.result] || display(result?.result)}${details.length ? "（" + details.join("、") + "）" : ""}`;
}

async function runChannelTest(trigger, feedback, destination) {
  trigger.disabled = true;
  formError(feedback, null);
  feedback.textContent = "正在发送测试通知…";
  try {
    feedback.textContent = await testChannel(destination);
  } catch (error) {
    formError(feedback, error);
  } finally {
    trigger.disabled = false;
  }
}

async function channelSettings() {
  const [settings, destinations] = await Promise.all([
    get("/notification-settings"), allPages("/notification-targets"),
  ]);
  const checks = new Map();
  const feedback = notice("");
  const rows = Object.entries(channelText).map(([channel, title]) => {
    const enabled = checkbox(channel, settings[channel]);
    enabled.setAttribute("aria-label", `${title}启用`);
    checks.set(channel, enabled);
    const actions = element("div", { class: "actions" });
    if (channel === "panel") {
      actions.append(button("发送测试通知", (event) => runChannelTest(event.currentTarget, feedback)));
      return [title, enabled, "在告警事件列表标记未读", actions];
    }
    actions.append(button("添加目标", () => destinationEditor(channel)));
    const matched = destinations.filter((item) => item.channel === channel);
    const targets = element("div", { class: "stack" }, matched.map((item) => element("div", {},
      item.name, meta(channel === "telegram" ? "会话 " + display(item.chat_id) : "收件人 " + display(item.recipients)),
      element("div", { class: "actions" }, button("编辑", () => destinationEditor(channel, item)),
        button("发送测试通知", (event) => runChannelTest(event.currentTarget, feedback, item))))));
    return [title, enabled, matched.length ? targets : "尚未配置", actions];
  });
  const save = submit("保存渠道开关");
  const form = element("form", { class: "list-page" },
    listTable("通知渠道", ["渠道", "启用", "配置", "操作"], rows), feedback,
    element("div", { class: "actions" }, save));
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    save.disabled = true;
    try {
      await api("/notification-settings", "PUT", Object.fromEntries([...checks].map(([key, value]) => [key, value.checked])));
      formError(feedback, null);
      feedback.textContent = "已保存渠道开关。";
    } catch (error) {
      formError(feedback, error);
    } finally {
      save.disabled = false;
    }
  });
  return form;
}

function destinationEditor(channel, current) {
  const telegram = channel === "telegram";
  const name = input("name", current?.name, { required: true, maxlength: 160 });
  const credential = input("credential_ref", current?.credential_ref, { required: telegram, placeholder: "<本机凭据文件绝对路径>" });
  const fields = [control("目标名称", name, true)];
  const generated = {};
  const append = (title, field, extra = {}, wide = false) => {
    generated[field] = input(field, current?.[field], extra);
    fields.push(control(title, generated[field], wide));
  };
  if (telegram) {
    append("会话 ID", "chat_id", { required: true });
    append("HTTP CONNECT 代理（可选）", "proxy_url", { type: "url" });
    fields.push(control("机器人凭据引用", credential, true));
  } else {
    append("SMTP 服务器", "host", { required: true });
    append("端口", "port", { type: "number", min: 1, max: 65535, placeholder: "默认端口" });
    generated.tls_mode = select("tls_mode", [["starttls", "强制 STARTTLS"], ["implicit", "隐式 TLS"]], current?.tls_mode);
    fields.push(control("传输安全", generated.tls_mode));
    append("登录用户（可选）", "username");
    append("发件人", "from", { type: "email", required: true });
    fields.push(control("邮箱凭据引用（可选）", credential));
    generated.recipients = element("textarea", { name: "recipients", required: true, placeholder: "每行一个收件地址" },
      (current?.recipients || []).join("\n"));
    fields.push(control("收件人", generated.recipients, true));
  }
  const feedback = notice("");
  const save = submit();
  const form = element("form", { class: "stack" }, element("div", { class: "fields" }, fields),
    feedback, element("div", { class: "form-actions" }, button("取消", closeDialog), save));
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const config = { name: name.value.trim(), channel, credential_ref: credential.value.trim() };
    for (const [field, node] of Object.entries(generated)) {
      if (field === "recipients") config[field] = node.value.split(/[\n,]+/).map((entry) => entry.trim()).filter(Boolean);
      else if (field === "port") config[field] = Number(node.value);
      else config[field] = node.value.trim();
    }
    save.disabled = true;
    try {
      await api(current ? `/notification-targets/${key(current.id)}` : "/notification-targets", current ? "PATCH" : "POST", config);
      closeDialog();
      notify("已保存通知目标。");
      render();
    } catch (error) {
      formError(feedback, error);
      save.disabled = false;
    }
  });
  showDialog(`${current ? "编辑" : "添加"}${channelText[channel]}目标`, form);
}

const updateMessages = {
  up_to_date: "当前版本已是最新正式版本。",
  no_release: "发布仓库暂无正式版本。",
  asset_missing: "新版暂无适用本机的安装包。",
  asset_unverified: "新版安装包未通过更新检查。",
  unconfigured: "尚未配置 GitHub 发布仓库。",
};

function closeVersion(restoreFocus = false) {
  versionPopover.hidden = true;
  versionTrigger.setAttribute("aria-expanded", "false");
  if (restoreFocus) versionTrigger.focus();
}

function githubUpdateLink(value, label) {
  if (!value) return null;
  try {
    const url = new URL(value);
    if (url.origin === "https://github.com" && !url.username && !url.password) {
      // Desktop WebViews hand same-frame external navigation to the system browser.
      return element("a", { href: url.href, target: desktop ? undefined : "_blank", rel: "noopener noreferrer" }, label);
    }
  } catch { /* Ignore invalid URLs returned by older versions. */ }
  return null;
}

function showVersionStatus() {
  const newer = updateInfo?.tag && ["available", "asset_missing", "asset_unverified"].includes(updateInfo.state);
  versionNumber.textContent = localVersion?.current || "";
  versionTrigger.hidden = !localVersion?.current;
  updateDot.hidden = !newer;
  versionTrigger.setAttribute("aria-label", newer ? `${localVersion.current}，有新版本` : localVersion?.current || "客户端版本");
  const repository = updateInfo?.repository || localVersion?.repository;
  const repositoryLink = githubUpdateLink(updateInfo?.repository_url || localVersion?.repository_url,
    repository ? `GitHub Releases · ${repository}` : "GitHub Releases");
  const releaseLink = newer ? githubUpdateLink(updateInfo.release_url, "在 GitHub 查看发布版本") : null;
  const mayApply = updateInfo?.state === "available" && updateInfo.can_apply;
  const assetLink = newer && !mayApply ? githubUpdateLink(updateInfo.asset_url, "下载安装包") : null;
  const status = versionFeedback || (updateInfo?.state === "available" && !mayApply ? "请下载适用于当前系统的安装包进行更新。" :
    updateMessages[updateInfo?.state] || (updateInfo ? "" : "正在检查更新…"));
  versionPopover.replaceChildren(...[element("h2", {}, newer ? `新版本 ${updateInfo.tag}` : `当前版本 ${localVersion?.current || ""}`),
    newer && updateInfo.release_name && updateInfo.release_name !== updateInfo.tag ? element("p", {}, updateInfo.release_name) : null,
    newer && updateInfo.release_notes ? element("p", { class: "release-notes muted" }, updateInfo.release_notes) : null,
    status ? notice(status, versionFailed) : null,
    releaseLink || assetLink || mayApply ? element("div", { class: "actions" }, releaseLink, assetLink,
      mayApply ? button("更新", applyUpdate, "primary", { disabled: updateRunning }) : null) : null,
    repositoryLink].filter(Boolean));
}

async function checkVersionAtStartup() {
  try {
    localVersion = await get("/version");
    if (localVersion.state === "rolled_back") {
      versionFeedback = "新版启动失败，已恢复原版本。";
      versionFailed = true;
    }
    showVersionStatus();
    updateInfo = await get("/version/update?startup=1");
  } catch {
    versionFeedback = "暂未获取更新信息。";
    versionFailed = true;
  }
  showVersionStatus();
}

async function applyUpdate() {
  if (updateRunning) return;
  const { tag, sha256 } = updateInfo;
  updateRunning = true;
  versionFailed = false;
  versionFeedback = "正在下载并校验更新…";
  showVersionStatus();
  try {
    const result = await api("/version/update/apply", "POST", { tag, sha256 });
    if (result?.state !== "restarting") throw new Error("未收到重启状态。");
    versionFeedback = "正在重启客户端…";
    showVersionStatus();
    if (desktop) return;
    const deadline = Date.now() + 90000;
    do {
      await new Promise((resolve) => setTimeout(resolve, 750));
      const current = await get("/version", { keepSession: true, signal: AbortSignal.timeout(4000) }).catch(() => null);
      if (current?.current === tag) {
        window.location.reload();
        return;
      }
      if (current?.state === "rolled_back") throw new Error("新版启动失败，已恢复原版本。");
    } while (Date.now() < deadline);
    throw new Error("未确认重启结果。请检查客户端状态。");
  } catch (error) {
    versionFailed = true;
    versionFeedback = error.message;
    updateRunning = false;
    showVersionStatus();
  }
}

versionTrigger.addEventListener("click", () => {
  if (!versionPopover.hidden) return closeVersion();
  versionPopover.hidden = false;
  versionTrigger.setAttribute("aria-expanded", "true");
});
document.addEventListener("click", (event) => {
  if (!versionPopover.hidden && !versionPopover.parentElement.contains(event.target)) closeVersion();
});
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && !versionPopover.hidden) closeVersion(true);
});

async function start() {
  sessionRetry.hidden = true;
  sessionStatus.textContent = "正在打开本地面板...";
  try {
    if (!desktop) await openWebSession();
    session.hidden = true;
    workspace.hidden = false;
    if (desktop) {
      for (const nav of document.querySelectorAll("[data-nav]")) nav.href = locationFor(nav.dataset.nav);
    }
    if (!["alerts", "event"].includes(routeQuery().get("view"))) refreshUnread();
    render();
    if (!versionChecked) {
      versionChecked = true;
      checkVersionAtStartup();
    }
  } catch (error) {
    sessionStatus.textContent = error.status >= 400 && error.status < 500 ? "本地会话未建立。" : "本地面板暂不可用，请确认客户端仍在运行。";
    sessionRetry.hidden = false;
  }
}

let versionChecked = false;
sessionRetry.addEventListener("click", start);
start();

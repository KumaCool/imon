import assert from "node:assert/strict";

export async function checkViewportLists(evaluate, labels) {
  const result = await evaluate(`(() => {
    const main = document.querySelector("main.content");
    return {
      scroll: main.scrollHeight > main.clientHeight + 1,
      lists: [...main.querySelectorAll(".inventory")].map((list) => ({
        label: list.getAttribute("aria-label"),
        inside: list.clientHeight >= 72 && list.getBoundingClientRect().bottom <= innerHeight,
        overflow: getComputedStyle(list).overflowY,
      })),
    };
  })()`);
  assert.deepEqual(result, {
    scroll: false,
    lists: labels.map((label) => ({ label, inside: true, overflow: "auto" })),
  });
}

export async function checkListLayout({ call, evaluate }) {
  const dimensions = (width, height) => call("Emulation.setDeviceMetricsOverride", {
    width, height, deviceScaleFactor: 1, mobile: false,
  });
  const box = (selector) => evaluate(`(() => {
    const bounds = document.querySelector(${JSON.stringify(selector)}).getBoundingClientRect();
    return { x: bounds.x + bounds.width / 2, y: bounds.y + bounds.height / 2 };
  })()`);
  const mouse = async (selector) => {
    const position = await box(selector);
    for (const type of ["mousePressed", "mouseReleased"]) {
      await call("Input.dispatchMouseEvent", { type, ...position, button: "left", clickCount: 1 });
    }
  };
  const key = (value) => evaluate(`document.activeElement.dispatchEvent(new KeyboardEvent(
    "keydown", { key: ${JSON.stringify(value)}, bubbles: true, cancelable: true }
  ))`);
  const sizes = () => evaluate(`(() => {
    const list = document.querySelector(".list-page .inventory");
    const main = document.querySelector("main.content");
    return {
      internal: list.scrollHeight > list.clientHeight,
      horizontal: list.scrollWidth > list.clientWidth,
      mainScroll: main.scrollHeight - main.clientHeight,
      documentScroll: document.documentElement.scrollHeight - innerHeight,
      documentWide: document.documentElement.scrollWidth > innerWidth,
      height: list.clientHeight,
      pagerVisible: document.querySelector(".fixture-pager").getBoundingClientRect().bottom <= innerHeight,
    };
  })()`);
  const original = ".host-row[data-layout-origin]";
  const trigger = `${original} .host-action-trigger`;
  const entries = ".host-action-menu:not([hidden]) [role=menuitem]";
  try {
    await evaluate(`(() => {
      const row = document.querySelector(".host-row");
      row.dataset.layoutOrigin = "";
      const table = row.closest("tbody");
      const list = row.closest(".inventory");
      const footer = document.createElement("button");
      footer.className = "fixture-pager";
      footer.textContent = "Fixture pagination";
      list.after(footer);
      for (let i = 0; i < 35; i++) {
        const sample = row.cloneNode(true);
        delete sample.dataset.layoutOrigin;
        sample.dataset.layoutSample = "";
        table.insertBefore(sample, row);
      }
    })()`);
    const wide = await sizes();
    assert.deepEqual(wide, {
      internal: true, horizontal: false, mainScroll: 0, documentScroll: 0, documentWide: false,
      height: wide.height, pagerVisible: true,
    }, "long inventory scrolls without moving the page or pagination");
    await dimensions(365, 640);
    const narrow = await sizes();
    assert.deepEqual(narrow, {
      internal: true, horizontal: true, mainScroll: 0, documentScroll: 0, documentWide: false,
      height: narrow.height, pagerVisible: true,
    }, "a narrow viewport contains both scroll axes within the inventory");
    assert.ok(narrow.height < wide.height, "table height tracks the available viewport");
    const header = await box(".inventory th:first-child");
    await call("Runtime.evaluate", {
      expression: `new Promise((done) => {
        const list = document.querySelector(".inventory");
        list.scrollTo(list.scrollWidth, list.scrollHeight);
        requestAnimationFrame(() => requestAnimationFrame(done));
      })`,
      awaitPromise: true,
    });
    assert.equal((await box(".inventory th:first-child")).y, header.y, "scrolling keeps column headers visible");
    await mouse(trigger);
    assert.equal(await evaluate(`document.querySelector(${JSON.stringify(trigger)}).getAttribute("aria-expanded")`), "true");
    assert.deepEqual(await evaluate(`[...document.querySelectorAll(${JSON.stringify(entries)})].map((node) => node.textContent)`),
      ["安装授权", "创建告警", "解绑"]);
    assert.equal(await evaluate("document.activeElement.textContent"), "安装授权");
    await key("ArrowDown");
    assert.equal(await evaluate("document.activeElement.textContent"), "创建告警");
    await key("End");
    assert.equal(await evaluate("document.activeElement.textContent"), "解绑");
    await key("Escape");
    assert.equal(await evaluate("document.activeElement.textContent"), "操作");
    assert.equal(await evaluate(`document.querySelector(${JSON.stringify(trigger)}).getAttribute("aria-expanded")`), "false");
    await key("ArrowUp");
    assert.equal(await evaluate("document.activeElement.textContent"), "解绑");
    await mouse(`${entries}:nth-child(3)`);
    assert.equal(await evaluate("document.querySelector('#dialog').open"), true, "bottom-row menu is clickable without clipping");
    assert.equal(await evaluate("document.querySelector('main.content h1').textContent"), "主机管理", "menu action does not open host details");
    await evaluate("document.querySelector('#dialog').close()");
    await evaluate(`(() => {
      document.querySelectorAll("[data-layout-sample]").forEach((row) => row.remove());
      const row = document.querySelector(${JSON.stringify(original)});
      row.hidden = true;
      const empty = document.createElement("tr");
      empty.dataset.layoutSample = "";
      const text = empty.insertCell();
      text.colSpan = 7;
      text.className = "empty";
      text.textContent = "Fixture empty";
      row.after(empty);
    })()`);
    const empty = await sizes();
    assert.equal(empty.internal, false, "empty table does not require scrolling");
    assert.equal(empty.height, narrow.height, "replacing rows with the empty state does not resize the table");
  } finally {
    await evaluate(`(() => {
      document.querySelectorAll("[data-layout-sample], .fixture-pager").forEach((node) => node.remove());
      const row = document.querySelector(${JSON.stringify(original)});
      if (row) {
        row.hidden = false;
        delete row.dataset.layoutOrigin;
        row.closest(".inventory").scrollTo(0, 0);
      }
    })()`);
    await dimensions(1280, 900);
  }
}

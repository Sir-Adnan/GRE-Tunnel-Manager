import { test } from "node:test";
import assert from "node:assert/strict";
import { copyText } from "../src/lib/clipboard.ts";

function browser(
  t,
  {
    clipboard,
    modal = false,
    result = true,
    throws = false,
    input = false,
  } = {},
) {
  const events = [];
  class Input {
    selectionStart = 2;
    selectionEnd = 5;
    selectionDirection = "backward";
    closest() {
      return modal ? dialog : null;
    }
    focus() {
      events.push("restore-focus");
    }
    setSelectionRange(...args) {
      events.push(["restore-input", ...args]);
    }
  }
  const range = {
    cloneRange() {
      return this;
    },
  };
  const selection = {
    rangeCount: 1,
    getRangeAt: () => range,
    removeAllRanges() {
      events.push("clear-selection");
    },
    addRange(value) {
      assert.equal(value, range);
      events.push("restore-selection");
    },
  };
  const field = {
    style: {},
    focus() {
      events.push("select-focus");
    },
    select() {
      events.push("select");
    },
    setSelectionRange(start, end) {
      assert.equal(start, 0);
      assert.equal(end, field.value.length);
    },
    remove() {
      events.push("remove");
    },
  };
  const dialog = {
    appendChild(value) {
      assert.equal(value, field);
      events.push("dialog");
    },
  };
  const active = input
    ? new Input()
    : {
        closest: () => (modal ? dialog : null),
        focus() {
          events.push("restore-focus");
        },
      };
  const document = {
    activeElement: active,
    getSelection: () => selection,
    body: {
      appendChild() {
        events.push("body");
      },
    },
    createElement(tag) {
      assert.equal(tag, "textarea");
      return field;
    },
    execCommand(command) {
      assert.equal(command, "copy");
      events.push("copy");
      if (throws) throw Error("denied");
      return result;
    },
  };
  for (const [name, value] of Object.entries({
    navigator: { clipboard },
    document,
    HTMLInputElement: Input,
    HTMLTextAreaElement: class {},
  })) {
    const descriptor = Object.getOwnPropertyDescriptor(globalThis, name);
    Object.defineProperty(globalThis, name, { configurable: true, value });
    t.after(() =>
      descriptor
        ? Object.defineProperty(globalThis, name, descriptor)
        : delete globalThis[name],
    );
  }
  return { events, field };
}

test("secure copy preserves exact IPv4, IPv6 and multiline text without a selection fallback", async (t) => {
  const copied = [];
  const { events } = browser(t, {
    clipboard: {
      async writeText(text) {
        copied.push(text);
      },
    },
  });
  for (const value of [
    "45.134.39.35",
    "2a0e:97c0:3ea:60::1",
    "global\n  maxconn 100000\n",
  ]) {
    assert.equal(await copyText(value), true);
  }
  assert.deepEqual(copied, [
    "45.134.39.35",
    "2a0e:97c0:3ea:60::1",
    "global\n  maxconn 100000\n",
  ]);
  assert.deepEqual(events, []);
});

test("HTTP without Clipboard API copies synchronously and restores the document selection", async (t) => {
  const { events, field } = browser(t);
  const result = copyText("2a0e:97c0:3ea:60::1");
  assert.ok(
    events.includes("copy"),
    "must run inside the click activation before awaiting",
  );
  assert.equal(await result, true);
  assert.equal(field.value, "2a0e:97c0:3ea:60::1");
  assert.deepEqual(events, [
    "body",
    "select-focus",
    "select",
    "copy",
    "remove",
    "restore-focus",
    "clear-selection",
    "restore-selection",
  ]);
});

test("denied Clipboard API falls back inside the modal and restores input selection", async (t) => {
  const { events } = browser(t, {
    clipboard: {
      async writeText() {
        throw Error("denied");
      },
    },
    modal: true,
    input: true,
  });
  assert.equal(await copyText("private-code"), true);
  assert.ok(events.includes("dialog"));
  assert.ok(!events.includes("body"));
  assert.deepEqual(events.at(-1), ["restore-input", 2, 5, "backward"]);
});

test("rejected selection copy never reports success and removes temporary secret text", async (t) => {
  const { events } = browser(t, { result: false });
  assert.equal(await copyText("token"), false);
  assert.ok(events.includes("remove"));
  assert.ok(events.includes("restore-focus"));
});

test("throwing selection copy returns failure and still restores focus", async (t) => {
  const { events } = browser(t, { throws: true });
  assert.equal(await copyText("token"), false);
  assert.ok(events.includes("remove"));
  assert.ok(events.includes("restore-focus"));
});

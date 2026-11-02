import test from "node:test";
import assert from "node:assert/strict";
import { ApiError, operate, transient } from "../src/lib/api.ts";

function respond(status, body) {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => {
      if (typeof body === "string") throw new SyntaxError("not JSON");
      return body;
    },
  };
}

test("a temporary polling failure does not report a running job as failed", async (t) => {
  const answers = [
    () => respond(202, { id: "job", state: "running" }),
    () => {
      throw new TypeError("network down");
    },
    () => respond(503, { error: "panel busy" }),
    () => respond(502, "<html>Bad gateway</html>"),
    () => respond(200, { id: "job", state: "completed" }),
  ];
  t.mock.method(globalThis, "fetch", async () => answers.shift()());
  t.mock.method(globalThis, "setTimeout", (resolve) => resolve());
  const seen = [];
  const job = await operate({ action: "plan" }, (value) =>
    seen.push(value.state),
  );
  assert.equal(job.state, "completed");
  assert.deepEqual(seen, ["running", "completed"]);
});

test("authentication and request errors stop polling immediately", async (t) => {
  globalThis.window = { dispatchEvent() {} };
  t.after(() => delete globalThis.window);
  const answers = [
    () => respond(202, { id: "job", state: "running" }),
    () => respond(401, { error: "sign in" }),
  ];
  t.mock.method(globalThis, "fetch", async () => answers.shift()());
  t.mock.method(globalThis, "setTimeout", (resolve) => resolve());
  await assert.rejects(operate({ action: "plan" }), /sign in/);
  assert.equal(transient(new ApiError("bad", 400)), false);
  assert.equal(transient(new ApiError("busy", 503)), true);
  assert.equal(transient(new TypeError("offline")), true);
});

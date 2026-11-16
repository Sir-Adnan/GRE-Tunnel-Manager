import test from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import {
  errorText,
  exactMessages,
  serverMessage,
} from "../src/lib/server-messages.ts";
import { server } from "../src/lib/i18n/messages/server.ts";
import { access } from "../src/lib/i18n/messages/access.ts";

const goRoot = new URL("../../", import.meta.url).pathname.replace(
  /^\/([A-Za-z]:)/,
  "$1",
);
function goSources(dir) {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    if (statSync(path).isDirectory())
      return name === "web" || name === "bin" ? [] : goSources(path);
    return name.endsWith(".go") && !name.endsWith("_test.go") ? [path] : [];
  });
}
const sources = goSources(goRoot)
  .map((path) => readFileSync(path, "utf8"))
  .join("\n");

test("every catalogued sentence is still a server string", () => {
  for (const sentence of Object.keys(exactMessages))
    assert.ok(
      sources.includes(JSON.stringify(sentence)),
      `the Go sources no longer contain "${sentence}"`,
    );
});

test("every catalogue key has both languages", () => {
  const known = { ...server, ...access };
  for (const key of new Set(Object.values(exactMessages))) {
    assert.ok(known[key], `missing message ${key}`);
    assert.ok(known[key][0] && known[key][1], key);
  }
  for (const [key, [en, fa]] of Object.entries(server)) {
    assert.ok(en && fa, key);
    assert.doesNotMatch(fa, /[۰-۹]/, `${key} uses Latin digits`);
  }
});

test("server answers translate; engine text stays as it is", () => {
  const fa = (key) => (key in server ? server[key][1] : key);
  assert.equal(
    errorText(new Error("incorrect code"), fa),
    server.srvIncorrectCode[1],
  );
  assert.equal(
    errorText(new Error("operation failed: panel busy"), fa),
    server.srvBusy[1],
  );
  assert.equal(
    errorText(new Error("the update could not start: unit exists"), fa),
    server.srvUpdateStart[1].replace("{e}", "unit exists"),
  );
  assert.equal(serverMessage("HTTP 502")?.key, "srvUnreachable");
  assert.equal(serverMessage("TypeError: Failed to fetch"), undefined);
  assert.equal(serverMessage("Failed to fetch")?.key, "srvUnreachable");
  assert.equal(
    errorText(new Error("Port is reserved by managed connection F1"), fa),
    "Port is reserved by managed connection F1",
  );
  assert.equal(errorText("plain", fa), "plain");
});

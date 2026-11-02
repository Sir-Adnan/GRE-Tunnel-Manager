import test from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";

// Message modules are read as text: they are plain object literals, and this keeps the test free of a bundler.
const folder = new URL("../src/lib/i18n/messages/", import.meta.url);
const modules = readdirSync(folder)
  .filter((name) => name.endsWith(".ts") && !["index.ts", "types.ts"].includes(name))
  .map((name) => ({ name, text: readFileSync(new URL(name, folder), "utf8") }));

function keys(text) {
  return [...text.matchAll(/^ {2}"?([A-Za-z0-9_-]+)"?: /gm)].map((match) => match[1]);
}

test("each message key lives in exactly one feature module", () => {
  const owner = new Map();
  for (const { name, text } of modules)
    for (const key of keys(text)) {
      assert.ok(!owner.has(key), `${key} is defined in ${owner.get(key)} and ${name}`);
      owner.set(key, name);
    }
  assert.ok(owner.size > 600);
  const index = readFileSync(new URL("index.ts", folder), "utf8");
  for (const { name } of modules) assert.match(index, new RegExp(`from "./${name.replace(".ts", "")}"`));
});

test("Persian messages use Latin display digits", () => {
  for (const { name, text } of modules) assert.doesNotMatch(text, /[۰-۹٠-٩]/, name);
});

test("every module is type-checked for both languages", () => {
  for (const { name, text } of modules) assert.match(text, /\} satisfies Messages;\s*$/, name);
});

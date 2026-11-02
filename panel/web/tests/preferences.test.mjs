import test from "node:test";
import assert from "node:assert/strict";
import {
  defaultPreferences,
  loadPreferences,
  parsePreferences,
  preferencesKey,
  savePreferences,
} from "../src/lib/preferences.ts";

const styles = ["signal", "graphite", "aurora", "nettinx", "neutral"];

function memoryStorage(entries = {}) {
  const data = new Map(Object.entries(entries));
  return {
    getItem: (key) => (data.has(key) ? data.get(key) : null),
    setItem: (key, value) => data.set(key, String(value)),
    removeItem: (key) => data.delete(key),
    data,
  };
}

test("new browsers start with the Signal dark default", () => {
  assert.deepEqual(
    loadPreferences(memoryStorage(), styles),
    defaultPreferences,
  );
  assert.equal(defaultPreferences.style, "signal");
  assert.equal(defaultPreferences.mode, "dark");
});

test("v1 settings move forward once and the old automatic Nettinx value becomes the new default", () => {
  const storage = memoryStorage({
    "gtm.preferences.v1": JSON.stringify({
      locale: "en",
      style: "nettinx",
      mode: "light",
      refresh: true,
    }),
  });
  const migrated = loadPreferences(storage, styles);
  assert.deepEqual(migrated, {
    locale: "en",
    style: "signal",
    mode: "light",
    refresh: true,
  });
  savePreferences(storage, { ...migrated, style: "nettinx" });
  assert.equal(storage.data.has("gtm.preferences.v1"), false);
  // A choice saved after the migration is honoured, Nettinx included.
  assert.equal(loadPreferences(storage, styles).style, "nettinx");
});

test("v1 styles other than the old default are kept", () => {
  const storage = memoryStorage({
    "gtm.preferences.v1": JSON.stringify({ style: "neutral" }),
  });
  assert.equal(loadPreferences(storage, styles).style, "neutral");
});

test("tampered or unknown values cannot reach the document", () => {
  const parsed = parsePreferences(
    { locale: "de", style: '"] body {', mode: "sepia", refresh: "yes" },
    styles,
  );
  assert.deepEqual(parsed, defaultPreferences);
  const broken = memoryStorage({ [preferencesKey]: "{not json" });
  assert.deepEqual(loadPreferences(broken, styles), defaultPreferences);
  assert.deepEqual(loadPreferences(undefined, styles), defaultPreferences);
});

test("blocked storage never breaks saving", () => {
  const blocked = {
    setItem() {
      throw new Error("blocked");
    },
    removeItem() {
      throw new Error("blocked");
    },
  };
  assert.doesNotThrow(() => savePreferences(blocked, defaultPreferences));
});

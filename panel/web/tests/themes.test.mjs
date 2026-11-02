import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const read = (path) => readFileSync(new URL(path, import.meta.url), "utf8");
const projectStyles = ["signal", "graphite", "aurora"];

function luminance(hex) {
  const channels = [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255);
  const [r, g, b] = channels.map((c) => (c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4));
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}
function contrast(a, b) {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (hi + 0.05) / (lo + 0.05);
}
function modes(css) {
  return [...css.matchAll(/\{([^}]+)\}/g)].map((block) =>
    Object.fromEntries([...block[1].matchAll(/--([\w-]+):\s*(#[0-9a-f]{6})/gi)].map((m) => [m[1], m[2]])),
  );
}

// Text and icon pairs the interface actually renders; the ring only needs non-text contrast.
const pairs = [
  ["foreground", "background", 4.5],
  ["foreground", "card", 4.5],
  ["muted-foreground", "background", 4.5],
  ["muted-foreground", "card", 4.5],
  ["muted-foreground", "muted", 4.5],
  ["primary-foreground", "primary", 4.5],
  ["primary-text", "background", 4.5],
  ["primary-text", "card", 4.5],
  ["secondary-foreground", "secondary", 4.5],
  ["accent-foreground", "accent", 4.5],
  ["popover-foreground", "popover", 4.5],
  ["destructive-foreground", "destructive", 4.5],
  ["destructive-text", "card", 4.5],
  ["success-foreground", "success", 4.5],
  ["success-text", "card", 4.5],
  ["warning-foreground", "warning", 4.5],
  ["warning-text", "card", 4.5],
  ["info-foreground", "info", 4.5],
  ["info-text", "card", 4.5],
  ["sidebar-foreground", "sidebar", 4.5],
  ["sidebar-accent-foreground", "sidebar-accent", 4.5],
  ["ring", "background", 3],
];

test("project presets meet WCAG AA for every rendered pair in both modes", () => {
  for (const id of projectStyles) {
    const [light, dark] = modes(read(`../src/experience/styles/${id}/tokens.css`));
    for (const [mode, tokens] of [["light", light], ["dark", dark]])
      for (const [text, surface, minimum] of pairs) {
        assert.ok(tokens[text] && tokens[surface], `${id}/${mode} defines ${text} and ${surface}`);
        const ratio = contrast(tokens[text], tokens[surface]);
        assert.ok(ratio >= minimum, `${id}/${mode} ${text} on ${surface} is ${ratio.toFixed(2)}:1`);
      }
  }
});

test("Signal is the default everywhere a default is declared, and every preset is registered", () => {
  assert.match(read("../index.html"), /data-style="signal"/);
  const pack = JSON.parse(read("../src/experience/packs/tunnel-admin/pack.json"));
  assert.equal(pack.defaultStyleId, "signal");
  assert.deepEqual(pack.compatibleStyleIds, ["signal", "graphite", "aurora", "nettinx", "neutral"]);
  const registry = read("../src/experience/registry.generated.ts");
  assert.match(registry, /defaultStyleId: "signal"/);
  const css = read("../src/experience/experience.generated.css");
  for (const id of pack.compatibleStyleIds) {
    assert.ok(css.includes(`styles/${id}/tokens.css`), `${id} stylesheet is imported`);
    assert.ok(registry.includes(`\n    ${id}: {`), `${id} is registered`);
  }
});

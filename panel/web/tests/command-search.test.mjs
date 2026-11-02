import test from "node:test";
import assert from "node:assert/strict";
import { matchCommands } from "../src/lib/command-search.ts";

const commands = [
  { id: "new-haproxy", group: "Create", label: "New HAProxy connection" },
  {
    id: "go-traffic",
    group: "Go to",
    label: "مصرف ترافیک",
    keywords: "traffic usage",
  },
  { id: "theme-signal", group: "Appearance", label: "Signal" },
];

test("every typed word must match, in any order and case", () => {
  assert.deepEqual(
    matchCommands(commands, "hap NEW").map((c) => c.id),
    ["new-haproxy"],
  );
  assert.deepEqual(
    matchCommands(commands, "appearance").map((c) => c.id),
    ["theme-signal"],
  );
  assert.deepEqual(matchCommands(commands, "  ").length, 3);
});

test("Persian labels are found by English keywords and by Persian text", () => {
  assert.deepEqual(
    matchCommands(commands, "traffic").map((c) => c.id),
    ["go-traffic"],
  );
  assert.deepEqual(
    matchCommands(commands, "ترافیک").map((c) => c.id),
    ["go-traffic"],
  );
});

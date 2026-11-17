import { test } from "node:test";
import assert from "node:assert/strict";
import { controllerCommand, controllerURL } from "../src/features/nodes/setup.ts";

test("controller setup accepts addresses without coupling browser HTTP to Agent TLS", () => {
 assert.equal(controllerURL("203.0.113.10"), "https://203.0.113.10:9443");
 assert.equal(controllerURL("2001:db8::10"), "https://[2001:db8::10]:9443");
 assert.equal(controllerURL("[2001:db8::10]"), "https://[2001:db8::10]:9443");
 assert.equal(controllerURL("panel.example.com"), "https://panel.example.com:9443");
 assert.ok(controllerCommand("203.0.113.10").includes("--url 'https://203.0.113.10:9443'"));
});

test("controller commands reject shell syntax and URL credential/path injection", () => {
 for (const host of ["$(id)", "x;id", "a'b", "https://example.com", "a/b", "a b", "a@b", "a\n--arg", "a:123", ":", "", "a".repeat(254)]) {
  assert.equal(controllerCommand(host), undefined, host);
 }
});

test("every copied installer command uses the download-then-run form that keeps the keyboard", async () => {
 const { installCommand, agentCommand } = await import("../src/lib/commands.ts");
 const { agentCommand: nodeAgent, agentTrafficCommand } = await import("../src/features/nodes/setup.ts");
 const base = 'sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/Sir-Adnan/GRE-Tunnel-Manager/main/install.sh)"';
 assert.equal(installCommand(), base);
 assert.equal(agentCommand(["--operations"]), `${base} @ --agent --operations`);
 assert.equal(nodeAgent, `${base} @ --agent`);
 assert.equal(agentTrafficCommand, `${base} @ --agent --traffic`);
 assert.equal(controllerCommand("panel.example.com"), "sudo gtm controller enable --url 'https://panel.example.com:9443'");
 for (const command of [installCommand(), nodeAgent, agentTrafficCommand]) assert.doesNotMatch(command, /\| *sudo bash|node-install\.sh/);
});

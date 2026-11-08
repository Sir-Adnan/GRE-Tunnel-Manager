import test from "node:test";
import assert from "node:assert/strict";
import { pairAddress } from "../src/features/nodes/pair-address.ts";

test("a pair defaults to the saved public IP only while it is on the server", () => {
  const addresses = ["78.47.250.5", "192.0.2.99", "2a01:4f8::1", "172.17.0.1"];
  assert.equal(pairAddress({ public_ip: "192.0.2.99", addresses }), "192.0.2.99");
  // The server's IP changed after installation: use the uplink's address.
  assert.equal(pairAddress({ public_ip: "198.51.100.4", addresses }), "78.47.250.5");
  assert.equal(pairAddress({ addresses: ["2a01:4f8::1", "78.47.250.5"] }), "78.47.250.5");
  assert.equal(pairAddress({ addresses: ["2a01:4f8::1"] }), "2a01:4f8::1");
  // Nothing local is known (an old node): the saved address is still shown.
  assert.equal(pairAddress({ public_ip: "198.51.100.4" }), "198.51.100.4");
  assert.equal(pairAddress(undefined), "");
});

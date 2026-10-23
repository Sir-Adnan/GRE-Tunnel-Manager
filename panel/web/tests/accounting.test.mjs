import test from "node:test";
import assert from "node:assert/strict";
import {cycleUsage,quotaUsage,csvCell} from "../src/features/traffic/accounting.ts";
test("cycle reset subtracts baselines without altering lifetime totals",()=>{
 const c={received:500,sent:200,baseline_received:400,baseline_sent:150};assert.deepEqual(cycleUsage(c),{received:100,sent:50});assert.equal(c.received,500);
 assert.equal(quotaUsage(c,{limit:140,direction:"total"}).reached,true);assert.equal(quotaUsage(c,{limit:140,direction:"received"}).reached,false);assert.equal(quotaUsage(c,{limit:0,direction:"total"}).percent,0);
});
test("CSV quotes values and neutralizes spreadsheet formulas",()=>{
 assert.equal(csvCell('a,"b"'),'"a,""b"""');assert.equal(csvCell(' =SUM(A1)'),'"\' =SUM(A1)"');assert.equal(csvCell(100),'"100"');
});

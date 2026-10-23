import test from "node:test";
import assert from "node:assert/strict";
import { archiveSamples } from "../src/features/traffic/history.ts";
import { number, uptime } from "../src/lib/format.ts";

const point=(time,received=100)=>({time,received,sent:20});
test("archive chart does not fabricate missing or future samples",()=>{
 assert.deepEqual(archiveSamples(undefined),[]);
 const history=[point('0001-01-01T00:00:00Z'),point('invalid'),point('2099-01-01T00:00:00Z'),point('2026-10-22T10:00:00Z')];
 assert.equal(archiveSamples({history},undefined,Date.parse('2026-10-23T10:00:00Z')).length,1);
});
test("duplicate timestamps do not create extra points and resets exclude old cycles",()=>{
 const history=[point('2026-10-22T10:00:00Z',100),point('2026-10-22T10:00:00Z',120),point('2026-10-22T10:01:00Z',30)];
 const now=Date.parse('2026-10-23T10:00:00Z');
 assert.equal(archiveSamples({history},undefined,now).length,2);
 assert.equal(archiveSamples({history},undefined,now)[0].received,120);
 const reset=archiveSamples({history},'2026-10-22T10:00:30Z',now);assert.equal(reset.length,1);assert.equal(reset[0].received,30);
});
test("charts are bounded and do not mutate selected-resource archives",()=>{
 const history=Array.from({length:400},(_,i)=>point(new Date(Date.UTC(2026,9,22,10,i)).toISOString(),i));
 const next=archiveSamples({history},undefined,Date.parse('2026-10-23T10:00:00Z'));
 assert.equal(next.length,288);assert.equal(next[0].received,112);assert.equal(history.length,400);
});
test("system-generated digits stay Latin in both languages while labels localize",()=>{
 assert.equal(number(123,'fa'),'123');assert.equal(number(123,'en'),'123');
 assert.equal(uptime('4h15m0s','fa'),'4 ساعت · 15 دقیقه');assert.equal(uptime('4h15m0s','en'),'4 h · 15 m');
});

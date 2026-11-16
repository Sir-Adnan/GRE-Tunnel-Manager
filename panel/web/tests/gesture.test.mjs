import test from "node:test";
import assert from "node:assert/strict";
import {
  barHidden,
  lockAxis,
  sheetOffset,
  sheetShouldClose,
  swipeOffset,
  swipeSettle,
} from "../src/lib/gesture.ts";

test("a touch picks an axis only after the slop and leans to scrolling", () => {
  assert.equal(lockAxis(4, 3), undefined);
  assert.equal(lockAxis(20, 4), "x");
  assert.equal(lockAxis(-20, 4), "x");
  assert.equal(lockAxis(10, 10), "y");
  assert.equal(lockAxis(2, -30), "y");
});

test("a sheet closes past a quarter of its height or on a downward flick", () => {
  assert.equal(sheetShouldClose(60, 0.1, 600), false);
  assert.equal(sheetShouldClose(130, 0.1, 600), true);
  assert.equal(sheetShouldClose(90, 0.1, 300), true);
  assert.equal(sheetShouldClose(30, 0.9, 600), true);
  assert.equal(sheetShouldClose(-200, 2, 600), false);
});

test("pulling a sheet up is resisted", () => {
  assert.equal(sheetOffset(40), 40);
  assert.ok(sheetOffset(-100) > -25);
});

const widths = { start: 72, end: 144 };

test("a swiped card opens past half its actions or on a flick", () => {
  assert.equal(swipeSettle(-80, 0, widths), "end");
  assert.equal(swipeSettle(-60, 0, widths), "none");
  assert.equal(swipeSettle(-30, -0.8, widths), "end");
  assert.equal(swipeSettle(40, 0, widths), "start");
  assert.equal(swipeSettle(20, 0.9, widths), "start");
  assert.equal(swipeSettle(20, 0, widths), "none");
});

test("a flick back closes an open card even before it passes half", () => {
  assert.equal(swipeSettle(-120, 0.8, widths), "none");
  assert.equal(swipeSettle(60, -0.8, widths), "none");
  assert.equal(swipeSettle(-120, 0.2, widths), "end");
});

test("a side without actions never opens", () => {
  assert.equal(swipeSettle(100, 1, { start: 0, end: 144 }), "none");
  assert.equal(swipeOffset(100, { start: 0, end: 144 }), 0);
});

test("a card follows the finger and resists beyond its actions", () => {
  assert.equal(swipeOffset(-50, widths), -50);
  const past = swipeOffset(-244, widths);
  assert.ok(past < -144 && past > -244);
});

test("the bottom bar hides while reading down and returns on the way up", () => {
  assert.equal(barHidden(false, { y: 400, dy: 20, atEnd: false }), true);
  assert.equal(barHidden(true, { y: 380, dy: -20, atEnd: false }), false);
  assert.equal(barHidden(true, { y: 400, dy: 2, atEnd: false }), true);
  assert.equal(barHidden(true, { y: 30, dy: 20, atEnd: false }), false);
  assert.equal(barHidden(true, { y: 900, dy: 20, atEnd: true }), false);
});

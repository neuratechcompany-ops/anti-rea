import assert from "node:assert/strict";
import test from "node:test";
import { requireProductionClock, resolveTrustedTime } from "../scripts/trusted-time.mjs";

test("uses the runner system clock when no override is supplied", () => {
  const clock = resolveTrustedTime(null, {}, () => 1_893_456_000_000);
  assert.deepEqual(clock, { source: "system", milliseconds: 1_893_456_000_000, observedAt: "2030-01-01T00:00:00.000Z" });
  assert.equal(requireProductionClock(clock), clock);
});

test("rejects caller-controlled historical time outside explicit test mode", () => {
  assert.throws(() => resolveTrustedTime("2020-01-01T00:00:00.000Z", {}), /forbidden outside explicit REA_TEST_MODE/);
});

test("labels test time so it cannot be used to sign a production gate", () => {
  const clock = resolveTrustedTime("2020-01-01T00:00:00.000Z", { REA_TEST_MODE: "1" });
  assert.equal(clock.source, "test-override");
  assert.throws(() => requireProductionClock(clock, "assessment gate signing"), /requires the production system clock/);
});

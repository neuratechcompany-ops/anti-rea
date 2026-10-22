export function resolveTrustedTime(override = null, environment = process.env, systemNow = Date.now) {
  if (override === null || override === undefined) {
    const milliseconds = systemNow();
    if (!Number.isFinite(milliseconds)) throw new Error("system clock is unavailable");
    return { source: "system", milliseconds, observedAt: new Date(milliseconds).toISOString() };
  }
  if (environment.REA_TEST_MODE !== "1") throw new Error("--now is forbidden outside explicit REA_TEST_MODE=1");
  const milliseconds = Date.parse(override);
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString() !== override) throw new Error("--now must be canonical ISO-8601");
  return { source: "test-override", milliseconds, observedAt: override };
}

export function requireProductionClock(clock, label = "operation") {
  if (clock?.source !== "system") throw new Error(`${label} requires the production system clock`);
  return clock;
}

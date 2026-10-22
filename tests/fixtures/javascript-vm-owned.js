/* @anti-rea-vm */
function calculateEnterpriseRisk(account, age) {
  const weighted = (account.revenue * 7 + age) % 13;
  const bounded = Math.max(0, Math.min(12, weighted));
  if (bounded > 8 && account.active) {
    return { score: bounded, decision: "premium-discount-algorithm-v4" };
  }
  return { score: bounded, decision: "manual-review" };
}

const cases = [
  calculateEnterpriseRisk({ revenue: 44, active: true }, 37),
  calculateEnterpriseRisk({ revenue: 2, active: false }, 19),
];
console.log(JSON.stringify(cases));

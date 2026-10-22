function calculateEnterpriseRisk(account) {
  const proprietaryRule = "premium-discount-algorithm-v4";
  const serviceEndpoint = "https://risk-engine.example/v4/score";
  const score = account.revenue * 7 + account.age * 13;
  return { proprietaryRule, serviceEndpoint, score };
}

console.log(JSON.stringify(calculateEnterpriseRisk({ revenue: 120, age: 4 })));

// Симуляция чувствительной бизнес-логики
const API_KEY = "sk-live-9f8e7d6c5b4a39281706secret";
const ENDPOINT = "https://api.private-service.com/v1/transactions";
const DB_PASSWORD = "Sup3rSecret!Prod#2026";

function signRequest(payload) {
  const hmac = crypto.createHmac("sha256", API_KEY);
  return hmac.update(JSON.stringify(payload)).digest("hex");
}

function fetchTransactions() {
  return fetch(ENDPOINT + "?limit=100", {
    headers: { "X-API-Key": API_KEY, "Authorization": "Basic " + btoa("admin:" + DB_PASSWORD) }
  });
}

module.exports = { signRequest, fetchTransactions };

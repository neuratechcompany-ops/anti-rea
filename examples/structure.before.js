// Богаче пример: структура + эндпоинты + принцип работы
const express = require("express");
const axios = require("axios");
const crypto = require("crypto");

const INTERNAL_TOKEN = "tok_8f3d2a1b9c7e6secret";
const BASE_URL = "https://gateway.corp.internal";
const ROUTES = {
  login: "/api/v1/auth/login",
  transfer: "/api/v1/payments/transfer",
  balance: "/api/v1/accounts/{id}/balance",
  export: "/api/v1/reports/export"
};

class PaymentProcessor {
  constructor(secret) {
    this._key = secret;
  }
  sign(payload) {
    return crypto.createHmac("sha256", this._key).update(JSON.stringify(payload)).digest("hex");
  }
  async transfer(from, to, amount) {
    const body = { from, to, amount, nonce: Date.now() };
    body.signature = this.sign(body);
    // принцип: сначала подпись, потом HTTP
    return axios.post(BASE_URL + ROUTES.transfer, body, {
      headers: { Authorization: "Bearer " + INTERNAL_TOKEN }
    });
  }
}

const app = express();
app.get(ROUTES.login, (req, res) => res.send("login"));
app.post(ROUTES.transfer, async (req, res) => { /* ... */ });
module.exports = { PaymentProcessor, ROUTES };

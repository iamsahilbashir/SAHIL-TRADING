import express from "express";
import http from "http";
import fs from "fs";
import path from "path";
import crypto from "crypto";
import { fileURLToPath } from "url";
import bcrypt from "bcryptjs";
import session from "express-session";
import { WebSocketServer, WebSocket } from "ws";
import dotenv from "dotenv";

dotenv.config();

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ server });

const PORT = process.env.PORT || 3000;
const KEY = process.env.TWELVE_DATA_API_KEY;
const DB = path.join(__dirname, "users.json");

if (!fs.existsSync(DB)) {
  fs.writeFileSync(DB, JSON.stringify({ users: [] }, null, 2));
}

const read = () =>
  JSON.parse(fs.readFileSync(DB, "utf8"));

const write = (x) =>
  fs.writeFileSync(DB, JSON.stringify(x, null, 2));

app.use(express.json());

app.use(
  session({
    secret: process.env.SESSION_SECRET || "CHANGE_ME",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax"
    }
  })
);

const auth = (q, r, n) =>
  q.session.user
    ? n()
    : r.status(401).json({ error: "Login required" });

app.post("/api/signup", async (q, r) => {
  let { name, email, password } = q.body || {};
  let d = read();
  let e = String(email || "").trim().toLowerCase();

  if (!name || !e || !password || password.length < 6) {
    return r
      .status(400)
      .json({ error: "Enter name, email and 6+ character password." });
  }

  if (d.users.some(u => u.email === e)) {
    return r
      .status(409)
      .json({ error: "Email already registered." });
  }

  let u = {
    id: crypto.randomUUID(),
    name: name.trim(),
    email: e,
    password: await bcrypt.hash(password, 12),
    balance: 10000,
    positions: [],
    history: [],
    watchlist: [
      "EUR/USD",
      "GBP/USD",
      "USD/JPY",
      "XAU/USD"
    ]
  };

  d.users.push(u);
  write(d);

  q.session.user = u.id;
  r.json({ ok: true });
});

app.post("/api/login", async (q, r) => {
  let { email, password } = q.body || {};
  let d = read();

  let u = d.users.find(
    x =>
      x.email ===
      String(email || "").trim().toLowerCase()
  );

  if (
    !u ||
    !(await bcrypt.compare(password || "", u.password))
  ) {
    return r
      .status(401)
      .json({ error: "Invalid login." });
  }

  q.session.user = u.id;
  r.json({ ok: true });
});

app.post("/api/logout", (q, r) => {
  q.session.destroy(() => r.json({ ok: true }));
});

app.get("/api/me", auth, (q, r) => {
  let u = read().users.find(
    x => x.id === q.session.user
  );

  if (!u) {
    return r.status(401).json({ error: "User not found" });
  }

  r.json({
    name: u.name,
    email: u.email,
    balance: u.balance,
    positions: u.positions,
    history: u.history,
    watchlist: u.watchlist
  });
});

app.post("/api/state", auth, (q, r) => {
  let d = read();
  let u = d.users.find(
    x => x.id === q.session.user
  );
  let b = q.body;

  if (!u) {
    return r.status(401).json({ error: "User not found" });
  }

  u.balance = Number(b.balance);
  u.positions = b.positions || [];
  u.history = b.history || [];
  u.watchlist = b.watchlist || u.watchlist;

  write(d);
  r.json({ ok: true });
});

app.use(express.static(path.join(__dirname, "public")));

let clients = new Set();

const send = o => {
  const s = JSON.stringify(o);

  for (const c of clients) {
    if (c.readyState === WebSocket.OPEN) {
      c.send(s);
    }
  }
};

const symbols = [
  "EUR/USD",
  "GBP/USD",
  "USD/JPY",
  "AUD/USD",
  "USD/CAD",
  "XAU/USD"
];

let priceIndex = 0;

async function updatePrice() {
  if (!KEY) {
    console.log("Twelve Data API key not configured.");
    return;
  }

  const symbol = symbols[priceIndex];
  priceIndex = (priceIndex + 1) % symbols.length;

  try {
    const url =
      "https://api.twelvedata.com/price?symbol=" +
      encodeURIComponent(symbol) +
      "&apikey=" +
      encodeURIComponent(KEY);

    const response = await fetch(url);
    const data = await response.json();

    if (data?.price) {
      send({
        type: "price",
        data: {
          symbol,
          price: Number(data.price)
        }
      });

      send({
        type: "status",
        connected: true
      });

      console.log(symbol, data.price);
    } else {
      console.log("Price error:", symbol, data);
    }
  } catch (err) {
    console.log("Price request failed:", err.message);

    send({
      type: "status",
      connected: false
    });
  }
}

wss.on("connection", c => {
  clients.add(c);

  c.send(
    JSON.stringify({
      type: "status",
      connected: true
    })
  );

  c.on("close", () => {
    clients.delete(c);
  });
});

updatePrice();
setInterval(updatePrice, 120000);

server.listen(PORT, "0.0.0.0", () => {
  console.log(
    "Sahil Trading Pro running on " + PORT
  );
});

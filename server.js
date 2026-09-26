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

let feed;
let clients = new Set();

const send = o => {
  let s = JSON.stringify(o);

  for (let c of clients) {
    if (c.readyState === WebSocket.OPEN) {
      c.send(s);
    }
  }
};

function connect() {
  if (!KEY) {
    console.log("Twelve Data API key not configured.");
    return;
  }

  try {
    feed = new WebSocket(
      "wss://ws.twelvedata.com/v1/quotes/price?apikey=" +
        encodeURIComponent(KEY)
    );

    feed.on("open", () => {
      console.log("Twelve Data connected.");

      feed.send(
        JSON.stringify({
          action: "subscribe",
          params: {
            symbols:
              "EUR/USD,GBP/USD,USD/JPY,AUD/USD,USD/CAD,XAU/USD"
          }
        })
      );

      send({
        type: "status",
        connected: true
      });
    });

    feed.on("message", d => {
      try {
        send({
          type: "price",
          data: JSON.parse(d)
        });
      } catch {}
    });

    feed.on("error", err => {
      console.log(
        "Twelve Data WebSocket error:",
        err.message
      );
    });

    feed.on("close", () => {
      console.log("Twelve Data disconnected.");

      send({
        type: "status",
        connected: false
      });

      feed = null;

      setTimeout(connect, 5000);
    });
  } catch (err) {
    console.log(
      "Twelve Data connection failed:",
      err.message
    );

    setTimeout(connect, 5000);
  }
}

connect();

wss.on("connection", c => {
  clients.add(c);

  c.send(
    JSON.stringify({
      type: "status",
      connected:
        !!(feed && feed.readyState === WebSocket.OPEN)
    })
  );

  c.on("close", () => {
    clients.delete(c);
  });
});

server.listen(PORT, () => {
  console.log(
    "Sahil Trading Pro running on " + PORT
  );
});

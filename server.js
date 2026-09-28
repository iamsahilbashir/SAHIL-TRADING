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

// ---------------- DATABASE ----------------

if (!fs.existsSync(DB)) {
  fs.writeFileSync(
    DB,
    JSON.stringify({ users: [] }, null, 2)
  );
}

const read = () =>
  JSON.parse(fs.readFileSync(DB, "utf8"));

const write = (x) =>
  fs.writeFileSync(
    DB,
    JSON.stringify(x, null, 2)
  );

// ---------------- MIDDLEWARE ----------------

app.use(express.json());

app.set("trust proxy", 1);

app.use(
  session({
    secret:
      process.env.SESSION_SECRET ||
      "CHANGE_THIS_SESSION_SECRET",

    resave: false,

    saveUninitialized: false,

    cookie: {
      httpOnly: true,
      sameSite: "lax",

      // Stay logged in for 30 days
      maxAge: 1000 * 60 * 60 * 24 * 30
    }
  })
);

// ---------------- AUTH ----------------

const auth = (q, r, n) => {
  if (q.session.user) {
    return n();
  }

  return r
    .status(401)
    .json({
      error: "Login required"
    });
};

// ---------------- SIGN UP ----------------

app.post("/api/signup", async (q, r) => {
  try {
    let {
      name,
      email,
      password
    } = q.body || {};

    let d = read();

    let e = String(email || "")
      .trim()
      .toLowerCase();

    name = String(name || "").trim();
    password = String(password || "");

    if (
      !name ||
      !e ||
      !password ||
      password.length < 6
    ) {
      return r
        .status(400)
        .json({
          error:
            "Enter name, email and 6+ character password."
        });
    }

    // Check duplicate account
    if (
      d.users.some(
        u => u.email === e
      )
    ) {
      return r
        .status(409)
        .json({
          error:
            "Email already registered. Please login."
        });
    }

    // Secure password hash
    const hashedPassword =
      await bcrypt.hash(password, 12);

    const u = {
      id: crypto.randomUUID(),

      name,

      email: e,

      password: hashedPassword,

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

    // Automatically login after signup
    q.session.user = u.id;

    q.session.save(err => {
      if (err) {
        console.log(
          "Session save error:",
          err.message
        );

        return r
          .status(500)
          .json({
            error:
              "Account created but login session failed."
          });
      }

      r.json({
        ok: true,
        message:
          "Account created successfully."
      });
    });

  } catch (err) {
    console.log(
      "Signup error:",
      err.message
    );

    r
      .status(500)
      .json({
        error:
          "Unable to create account."
      });
  }
});

// ---------------- LOGIN ----------------

app.post("/api/login", async (q, r) => {
  try {
    let {
      email,
      password
    } = q.body || {};

    let d = read();

    let e = String(email || "")
      .trim()
      .toLowerCase();

    password = String(password || "");

    let u = d.users.find(
      x => x.email === e
    );

    if (
      !u ||
      !(await bcrypt.compare(
        password,
        u.password
      ))
    ) {
      return r
        .status(401)
        .json({
          error:
            "Invalid email or password."
        });
    }

    // Create login session
    q.session.user = u.id;

    q.session.save(err => {
      if (err) {
        console.log(
          "Session save error:",
          err.message
        );

        return r
          .status(500)
          .json({
            error:
              "Login session could not be saved."
          });
      }

      r.json({
        ok: true,
        message:
          "Login successful."
      });
    });

  } catch (err) {
    console.log(
      "Login error:",
      err.message
    );

    r
      .status(500)
      .json({
        error:
          "Unable to login."
      });
  }
});

// ---------------- LOGOUT ----------------

app.post("/api/logout", (q, r) => {
  q.session.destroy(err => {

    if (err) {
      console.log(
        "Logout error:",
        err.message
      );

      return r
        .status(500)
        .json({
          error:
            "Logout failed."
        });
    }

    // Remove session cookie
    r.clearCookie("connect.sid");

    r.json({
      ok: true,
      message:
        "Logged out successfully."
    });
  });
});

// ---------------- CURRENT USER ----------------

app.get("/api/me", auth, (q, r) => {

  let d = read();

  let u = d.users.find(
    x =>
      x.id ===
      q.session.user
  );

  if (!u) {

    q.session.destroy(() => {});

    return r
      .status(401)
      .json({
        error:
          "User account not found."
      });
  }

  r.json({
    name: u.name,

    email: u.email,

    balance: u.balance,

    positions:
      u.positions || [],

    history:
      u.history || [],

    watchlist:
      u.watchlist || []
  });
});

// ---------------- SAVE ACCOUNT STATE ----------------

app.post("/api/state", auth, (q, r) => {

  let d = read();

  let u = d.users.find(
    x =>
      x.id ===
      q.session.user
  );

  let b = q.body || {};

  if (!u) {
    return r
      .status(401)
      .json({
        error:
          "User not found"
      });
  }

  u.balance =
    Number(b.balance);

  u.positions =
    b.positions || [];

  u.history =
    b.history || [];

  u.watchlist =
    b.watchlist ||
    u.watchlist;

  write(d);

  r.json({
    ok: true
  });
});

// ---------------- WEBSITE ----------------

app.use(
  express.static(
    path.join(
      __dirname,
      "public"
    )
  )
);

// ---------------- MARKET DATA ----------------

let clients = new Set();

const send = o => {

  const s =
    JSON.stringify(o);

  for (const c of clients) {

    if (
      c.readyState ===
      WebSocket.OPEN
    ) {
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

    console.log(
      "Twelve Data API key not configured."
    );

    return;
  }

  const symbol =
    symbols[priceIndex];

  priceIndex =
    (priceIndex + 1) %
    symbols.length;

  try {

    const url =
      "https://api.twelvedata.com/price?symbol=" +
      encodeURIComponent(symbol) +
      "&apikey=" +
      encodeURIComponent(KEY);

    const response =
      await fetch(url);

    const data =
      await response.json();

    if (data?.price) {

      send({
        type: "price",

        data: {
          symbol,

          price:
            Number(data.price)
        }
      });

      send({
        type: "status",

        connected: true
      });

      console.log(
        symbol,
        data.price
      );

    } else {

      console.log(
        "Price error:",
        symbol,
        data
      );
    }

  } catch (err) {

    console.log(
      "Price request failed:",
      err.message
    );

    send({
      type: "status",

      connected: false
    });
  }
}

// ---------------- WEBSOCKET ----------------

wss.on(
  "connection",
  c => {

    clients.add(c);

    c.send(
      JSON.stringify({
        type: "status",

        connected: true
      })
    );

    c.on(
      "close",
      () => {
        clients.delete(c);
      }
    );
  }
);

// First price request
updatePrice();

// Next request every 2 minutes
setInterval(
  updatePrice,
  120000
);

// ---------------- START SERVER ----------------

server.listen(
  PORT,
  "0.0.0.0",
  () => {

    console.log(
      "Sahil Trading Pro running on " +
      PORT
    );
  }
);

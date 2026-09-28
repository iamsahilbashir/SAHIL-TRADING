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

// ===============================
// BASIC SETUP
// ===============================

const __dirname = path.dirname(
  fileURLToPath(import.meta.url)
);

const app = express();

const server = http.createServer(app);

const wss = new WebSocketServer({
  server
});

const PORT =
  process.env.PORT || 3000;

const KEY =
  process.env.TWELVE_DATA_API_KEY;

const DB =
  path.join(__dirname, "users.json");

// ===============================
// DATABASE
// ===============================

if (!fs.existsSync(DB)) {
  fs.writeFileSync(
    DB,
    JSON.stringify(
      { users: [] },
      null,
      2
    )
  );
}

const read = () => {
  try {
    return JSON.parse(
      fs.readFileSync(DB, "utf8")
    );
  } catch {
    return { users: [] };
  }
};

const write = data => {
  fs.writeFileSync(
    DB,
    JSON.stringify(
      data,
      null,
      2
    )
  );
};

// ===============================
// MIDDLEWARE
// ===============================

app.use(express.json());

app.set(
  "trust proxy",
  1
);

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

      // Keep user logged in for 30 days
      maxAge:
        1000 *
        60 *
        60 *
        24 *
        30
    }
  })
);

// ===============================
// AUTH MIDDLEWARE
// ===============================

const auth = (req, res, next) => {

  if (req.session.user) {
    return next();
  }

  return res
    .status(401)
    .json({
      error:
        "Login required"
    });
};

// ===============================
// CREATE ACCOUNT
// ===============================

app.post(
  "/api/signup",
  async (req, res) => {

    try {

      let {
        name,
        email,
        password
      } = req.body || {};

      name =
        String(name || "")
          .trim();

      email =
        String(email || "")
          .trim()
          .toLowerCase();

      password =
        String(password || "");

      const db = read();

      // Basic validation
      if (
        !name ||
        !email ||
        !password ||
        password.length < 6
      ) {

        return res
          .status(400)
          .json({
            error:
              "Enter name, email and 6+ character password."
          });
      }

      // Check duplicate email
      const exists =
        db.users.some(
          user =>
            user.email === email
        );

      if (exists) {

        return res
          .status(409)
          .json({
            error:
              "Email already registered. Please login."
          });
      }

      // Secure password hash
      const hashedPassword =
        await bcrypt.hash(
          password,
          12
        );

      const user = {

        id:
          crypto.randomUUID(),

        name,

        email,

        password:
          hashedPassword,

        // Demo account balance
        balance:
          10000,

        positions: [],

        history: [],

        watchlist: [
          "EUR/USD",
          "GBP/USD",
          "USD/JPY",
          "XAU/USD"
        ]
      };

      db.users.push(user);

      write(db);

      // Automatically login
      req.session.user =
        user.id;

      req.session.save(
        err => {

          if (err) {

            console.log(
              "Session save error:",
              err.message
            );

            return res
              .status(500)
              .json({
                error:
                  "Account created but login session failed."
              });
          }

          res.json({
            ok: true,
            message:
              "Account created successfully."
          });
        }
      );

    } catch (err) {

      console.log(
        "Signup error:",
        err.message
      );

      res
        .status(500)
        .json({
          error:
            "Unable to create account."
        });
    }
  }
);

// ===============================
// LOGIN
// ===============================

app.post(
  "/api/login",
  async (req, res) => {

    try {

      let {
        email,
        password
      } = req.body || {};

      email =
        String(email || "")
          .trim()
          .toLowerCase();

      password =
        String(password || "");

      const db = read();

      const user =
        db.users.find(
          u =>
            u.email === email
        );

      if (
        !user ||
        !(await bcrypt.compare(
          password,
          user.password
        ))
      ) {

        return res
          .status(401)
          .json({
            error:
              "Invalid email or password."
          });
      }

      req.session.user =
        user.id;

      req.session.save(
        err => {

          if (err) {

            console.log(
              "Session save error:",
              err.message
            );

            return res
              .status(500)
              .json({
                error:
                  "Login session could not be saved."
              });
          }

          res.json({
            ok: true,
            message:
              "Login successful."
          });
        }
      );

    } catch (err) {

      console.log(
        "Login error:",
        err.message
      );

      res
        .status(500)
        .json({
          error:
            "Unable to login."
        });
    }
  }
);

// ===============================
// LOGOUT
// ===============================

app.post(
  "/api/logout",
  (req, res) => {

    req.session.destroy(
      err => {

        if (err) {

          console.log(
            "Logout error:",
            err.message
          );

          return res
            .status(500)
            .json({
              error:
                "Logout failed."
            });
        }

        res.clearCookie(
          "connect.sid"
        );

        res.json({
          ok: true,
          message:
            "Logged out successfully."
        });
      }
    );
  }
);

// ===============================
// CURRENT USER
// ===============================

app.get(
  "/api/me",
  auth,
  (req, res) => {

    const db = read();

    const user =
      db.users.find(
        u =>
          u.id ===
          req.session.user
      );

    if (!user) {

      req.session.destroy(
        () => {}
      );

      return res
        .status(401)
        .json({
          error:
            "User account not found."
        });
    }

    res.json({

      name:
        user.name,

      email:
        user.email,

      balance:
        user.balance,

      positions:
        user.positions || [],

      history:
        user.history || [],

      watchlist:
        user.watchlist || []
    });
  }
);

// ===============================
// SAVE USER STATE
// ===============================

app.post(
  "/api/state",
  auth,
  (req, res) => {

    const db = read();

    const user =
      db.users.find(
        u =>
          u.id ===
          req.session.user
      );

    if (!user) {

      return res
        .status(401)
        .json({
          error:
            "User not found."
        });
    }

    const body =
      req.body || {};

    user.balance =
      Number(body.balance);

    user.positions =
      body.positions || [];

    user.history =
      body.history || [];

    user.watchlist =
      body.watchlist ||
      user.watchlist;

    write(db);

    res.json({
      ok: true
    });
  }
);

// ===============================
// PUBLIC WEBSITE
// ===============================

app.use(
  express.static(
    path.join(
      __dirname,
      "public"
    )
  )
);

// ===============================
// MARKET DATA
// ===============================

let clients =
  new Set();

let latestPrices =
  {};

// Send message to connected users
const send = data => {

  const message =
    JSON.stringify(data);

  for (
    const client of clients
  ) {

    if (
      client.readyState ===
      WebSocket.OPEN
    ) {

      client.send(message);
    }
  }
};

// Demo market symbols
const symbols = [

  "EUR/USD",

  "GBP/USD",

  "USD/JPY",

  "AUD/USD",

  "USD/CAD",

  "XAU/USD"
];

// ===============================
// GET ONE PRICE
// ===============================

async function updatePrice(
  symbol
) {

  if (!KEY) {

    console.log(
      "Twelve Data API key not configured."
    );

    return;
  }

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

    if (
      data &&
      data.price
    ) {

      const price =
        Number(data.price);

      latestPrices[symbol] =
        price;

      // Send new price
      send({

        type:
          "price",

        data: {

          symbol,

          price
        }
      });

      console.log(
        symbol,
        price
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
      symbol,
      err.message
    );
  }
}

// ===============================
// UPDATE ALL PRICES
// ===============================

async function updateAllPrices() {

  console.log(
    "Updating all market prices..."
  );

  // Get all 6 symbols
  // together
  await Promise.all(
    symbols.map(
      symbol =>
        updatePrice(symbol)
    )
  );

  // Market status
  send({

    type:
      "status",

    connected:
      Object.keys(
        latestPrices
      ).length > 0
  });

  console.log(
    "Market price update complete."
  );
}

// ===============================
// WEBSOCKET CONNECTION
// ===============================

wss.on(
  "connection",
  client => {

    clients.add(client);

    console.log(
      "WebSocket client connected."
    );

    // Send already available
    // prices immediately
    for (
      const symbol of symbols
    ) {

      if (
        latestPrices[symbol]
      ) {

        client.send(
          JSON.stringify({

            type:
              "price",

            data: {

              symbol,

              price:
                latestPrices[
                  symbol
                ]
            }
          })
        );
      }
    }

    // Send market status
    client.send(
      JSON.stringify({

        type:
          "status",

        connected:
          Object.keys(
            latestPrices
          ).length > 0
      })
    );

    client.on(
      "close",
      () => {

        clients.delete(
          client
        );

        console.log(
          "WebSocket client disconnected."
        );
      }
    );
  }
);

// ===============================
// START MARKET DATA
// ===============================

// Get all prices immediately
updateAllPrices();

// Refresh every 12 minutes
setInterval(
  updateAllPrices,
  12 * 60 * 1000
);

// ===============================
// START SERVER
// ===============================

server.listen(
  PORT,
  "0.0.0.0",
  () => {

    console.log(
      "Sahil Trading Pro running on port " +
      PORT
    );
  }
);

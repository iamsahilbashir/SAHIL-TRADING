import express from "express";
import http from "http";
import fs from "fs";
import path from "path";
import crypto from "crypto";
import { fileURLToPath } from "url";
import bcrypt from "bcryptjs";
import session from "express-session";
import connectPgSimple from "connect-pg-simple";
import { Pool } from "pg";
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

const PORT = process.env.PORT || 3000;
const KEY = process.env.TWELVE_DATA_API_KEY;
const DATABASE_URL = process.env.DATABASE_URL;

// ===============================
// DATABASE CHECK
// ===============================

if (!DATABASE_URL) {
  console.error(
    "ERROR: DATABASE_URL is missing in Render Environment Variables."
  );
  process.exit(1);
}

// ===============================
// POSTGRES DATABASE
// ===============================

const pool = new Pool({
  connectionString: DATABASE_URL,

  ssl:
    process.env.NODE_ENV === "production"
      ? { rejectUnauthorized: false }
      : false
});

// ===============================
// SESSION STORE
// ===============================

const PgStore = connectPgSimple(session);

const sessionStore = new PgStore({
  pool,
  tableName: "session",
  createTableIfMissing: true
});

// ===============================
// MIDDLEWARE
// ===============================

app.use(
  express.json({
    limit: "1mb"
  })
);

app.set("trust proxy", 1);

app.use(
  session({
    store: sessionStore,

    secret:
      process.env.SESSION_SECRET ||
      "CHANGE_THIS_SESSION_SECRET",

    resave: false,

    saveUninitialized: false,

    cookie: {
      httpOnly: true,

      sameSite: "lax",

      secure:
        process.env.NODE_ENV === "production",

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
// CREATE DATABASE TABLE
// ===============================

async function createTables() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,

      balance DOUBLE PRECISION NOT NULL DEFAULT 10000,

      positions JSONB NOT NULL DEFAULT '[]'::jsonb,

      history JSONB NOT NULL DEFAULT '[]'::jsonb,

      watchlist JSONB NOT NULL DEFAULT
        '["EUR/USD","GBP/USD","USD/JPY","XAU/USD"]'::jsonb,

      notes TEXT NOT NULL DEFAULT '',

      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  console.log("PostgreSQL tables ready.");
}

// ===============================
// OLD users.json MIGRATION
// ===============================

const OLD_DB = path.join(
  __dirname,
  "users.json"
);

async function migrateOldUsers() {
  if (!fs.existsSync(OLD_DB)) {
    console.log("No old users.json found.");
    return;
  }

  try {
    const raw = fs.readFileSync(
      OLD_DB,
      "utf8"
    );

    const parsed = JSON.parse(raw);

    if (
      !parsed ||
      !Array.isArray(parsed.users)
    ) {
      return;
    }

    for (const oldUser of parsed.users) {
      if (
        !oldUser ||
        !oldUser.email ||
        !oldUser.password
      ) {
        continue;
      }

      await pool.query(
        `
        INSERT INTO users (
          id,
          name,
          email,
          password_hash,
          balance,
          positions,
          history,
          watchlist,
          notes
        )
        VALUES (
          $1,$2,$3,$4,$5,$6,$7,$8,$9
        )
        ON CONFLICT (email)
        DO NOTHING
        `,
        [
          oldUser.id ||
            crypto.randomUUID(),

          oldUser.name ||
            "Trader",

          String(
            oldUser.email
          )
            .trim()
            .toLowerCase(),

          oldUser.password,

          typeof oldUser.balance ===
          "number"
            ? oldUser.balance
            : 10000,

          JSON.stringify(
            Array.isArray(
              oldUser.positions
            )
              ? oldUser.positions
              : []
          ),

          JSON.stringify(
            Array.isArray(
              oldUser.history
            )
              ? oldUser.history
              : []
          ),

          JSON.stringify(
            Array.isArray(
              oldUser.watchlist
            )
              ? oldUser.watchlist
              : [
                  "EUR/USD",
                  "GBP/USD",
                  "USD/JPY",
                  "XAU/USD"
                ]
          ),

          typeof oldUser.notes ===
          "string"
            ? oldUser.notes
            : ""
        ]
      );
    }

    console.log(
      "Old users.json migration checked."
    );

  } catch (err) {
    console.log(
      "Old users migration error:",
      err.message
    );
  }
}

// ===============================
// DEFAULT USER DATA
// ===============================

const defaultWatchlist = [
  "EUR/USD",
  "GBP/USD",
  "USD/JPY",
  "XAU/USD"
];

// ===============================
// AUTH MIDDLEWARE
// ===============================

const auth = (
  req,
  res,
  next
) => {

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

      const existing =
        await pool.query(
          `
          SELECT id
          FROM users
          WHERE email = $1
          `,
          [email]
        );

      if (
        existing.rows.length > 0
      ) {

        return res
          .status(409)
          .json({
            error:
              "Email already registered. Please login."
          });
      }

      const hashedPassword =
        await bcrypt.hash(
          password,
          12
        );

      const userId =
        crypto.randomUUID();

      await pool.query(
        `
        INSERT INTO users (
          id,
          name,
          email,
          password_hash,
          balance,
          positions,
          history,
          watchlist,
          notes
        )
        VALUES (
          $1,
          $2,
          $3,
          $4,
          $5,
          $6,
          $7,
          $8,
          $9
        )
        `,
        [
          userId,

          name,

          email,

          hashedPassword,

          10000,

          JSON.stringify([]),

          JSON.stringify([]),

          JSON.stringify(
            defaultWatchlist
          ),

          ""
        ]
      );

      req.session.user =
        userId;

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

      const result =
        await pool.query(
          `
          SELECT *
          FROM users
          WHERE email = $1
          `,
          [email]
        );

      const user =
        result.rows[0];

      if (
        !user ||
        !(await bcrypt.compare(
          password,
          user.password_hash
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
  async (req, res) => {

    try {

      const result =
        await pool.query(
          `
          SELECT
            id,
            name,
            email,
            balance,
            positions,
            history,
            watchlist,
            notes
          FROM users
          WHERE id = $1
          `,
          [req.session.user]
        );

      const user =
        result.rows[0];

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
          Number(user.balance),

        positions:
          user.positions || [],

        history:
          user.history || [],

        watchlist:
          user.watchlist ||
          defaultWatchlist,

        notes:
          user.notes || ""
      });

    } catch (err) {

      console.log(
        "Current user error:",
        err.message
      );

      res
        .status(500)
        .json({
          error:
            "Unable to load account."
        });
    }
  }
);

// ===============================
// SAVE USER STATE
// ===============================

app.post(
  "/api/state",
  auth,
  async (req, res) => {

    try {

      const body =
        req.body || {};

      const result =
        await pool.query(
          `
          SELECT id
          FROM users
          WHERE id = $1
          `,
          [req.session.user]
        );

      if (
        result.rows.length === 0
      ) {

        return res
          .status(401)
          .json({
            error:
              "User not found."
          });
      }

      const updates = [];
      const values = [];

      let index = 1;

      if (
        body.balance !== undefined
      ) {

        const balance =
          Number(
            body.balance
          );

        if (
          Number.isFinite(
            balance
          )
        ) {

          updates.push(
            `balance = $${index++}`
          );

          values.push(
            balance
          );
        }
      }

      if (
        Array.isArray(
          body.positions
        )
      ) {

        updates.push(
          `positions = $${index++}::jsonb`
        );

        values.push(
          JSON.stringify(
            body.positions
          )
        );
      }

      if (
        Array.isArray(
          body.history
        )
      ) {

        updates.push(
          `history = $${index++}::jsonb`
        );

        values.push(
          JSON.stringify(
            body.history
          )
        );
      }

      if (
        Array.isArray(
          body.watchlist
        )
      ) {

        updates.push(
          `watchlist = $${index++}::jsonb`
        );

        values.push(
          JSON.stringify(
            body.watchlist
          )
        );
      }

      if (
        typeof body.notes ===
        "string"
      ) {

        updates.push(
          `notes = $${index++}`
        );

        values.push(
          body.notes
        );
      }

      updates.push(
        `updated_at = NOW()`
      );

      values.push(
        req.session.user
      );

      await pool.query(
        `
        UPDATE users
        SET ${updates.join(", ")}
        WHERE id = $${index}
        `,
        values
      );

      res.json({
        ok: true
      });

    } catch (err) {

      console.log(
        "State save error:",
        err.message
      );

      res
        .status(500)
        .json({
          error:
            "Unable to save account state."
        });
    }
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

const clients =
  new Set();

const latestPrices =
  {};

const latestVolumes =
  {};

const latestQuotes =
  {};

// ===============================
// SEND WEBSOCKET MESSAGE
// ===============================

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

// ===============================
// MARKET SYMBOLS
// ===============================

const symbols = [

  "EUR/USD",
  "GBP/USD",
  "USD/JPY",
  "USD/CHF",
  "AUD/USD",
  "USD/CAD",
  "NZD/USD",

  "EUR/GBP",
  "EUR/JPY",
  "GBP/JPY",
  "EUR/CHF",

  "AUD/JPY",
  "CAD/JPY",
  "NZD/JPY",

  "XAU/USD",
  "XAG/USD",

  "BTC/USD",
  "ETH/USD"
];

// ===============================
// GET ONE QUOTE
// ===============================

async function updateQuote(symbol) {

  if (!KEY) {

    console.log(
      "Twelve Data API key not configured."
    );

    return;
  }

  try {

    const url =
      "https://api.twelvedata.com/quote?symbol=" +
      encodeURIComponent(symbol) +
      "&apikey=" +
      encodeURIComponent(KEY);

    const response =
      await fetch(url);

    const data =
      await response.json();

    if (
      !data ||
      data.status === "error"
    ) {

      console.log(
        "Quote error:",
        symbol,
        data
      );

      return;
    }

    const price =
      Number(
        data.close ??
        data.price ??
        data.last
      );

    if (
      !Number.isFinite(price)
    ) {

      console.log(
        "Invalid quote price:",
        symbol,
        data
      );

      return;
    }

    let volume = null;

    if (
      data.volume !== undefined &&
      data.volume !== null &&
      data.volume !== ""
    ) {

      const parsedVolume =
        Number(data.volume);

      if (
        Number.isFinite(
          parsedVolume
        )
      ) {

        volume =
          parsedVolume;
      }
    }

    latestPrices[symbol] =
      price;

    latestVolumes[symbol] =
      volume;

    latestQuotes[symbol] = {
      symbol,
      price,
      volume,
      change:
        Number(
          data.change
        ) || 0,
      percent_change:
        Number(
          data.percent_change
        ) || 0,
      timestamp:
        Date.now()
    };

    send({

      type:
        "market",

      data:
        latestQuotes[symbol]
    });

    console.log(
      symbol,
      "price:",
      price,
      "volume:",
      volume
    );

  } catch (err) {

    console.log(
      "Quote request failed:",
      symbol,
      err.message
    );
  }
}

// ===============================
// UPDATE ALL MARKET DATA
// ===============================

async function updateAllPrices() {

  console.log(
    "Updating market prices and volume..."
  );

  if (!KEY) {

    console.log(
      "TWELVE_DATA_API_KEY is missing."
    );

    send({

      type:
        "status",

      connected:
        false
    });

    return;
  }

  /*
   * Small batches prevent sending
   * all API requests at exactly
   * the same moment.
   */

  for (
    let i = 0;
    i < symbols.length;
    i += 4
  ) {

    const batch =
      symbols.slice(
        i,
        i + 4
      );

    await Promise.all(
      batch.map(
        symbol =>
          updateQuote(symbol)
      )
    );
  }

  send({

    type:
      "status",

    connected:
      Object.keys(
        latestPrices
      ).length > 0,

    symbols:
      Object.keys(
        latestPrices
      ).length,

    updatedAt:
      Date.now()
  });

  console.log(
    "Market update complete."
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

    // Send current market data
    for (
      const symbol of symbols
    ) {

      if (
        latestQuotes[symbol]
      ) {

        client.send(
          JSON.stringify({

            type:
              "market",

            data:
              latestQuotes[
                symbol
              ]
          })
        );

      } else if (
        latestPrices[symbol]
      ) {

        client.send(
          JSON.stringify({

            type:
              "market",

            data: {

              symbol,

              price:
                latestPrices[
                  symbol
                ],

              volume:
                latestVolumes[
                  symbol
                ] ?? null
            }
          })
        );
      }
    }

    // Market status
    client.send(
      JSON.stringify({

        type:
          "status",

        connected:
          Object.keys(
            latestPrices
          ).length > 0,

        symbols:
          Object.keys(
            latestPrices
          ).length
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

    client.on(
      "error",
      err => {

        console.log(
          "WebSocket client error:",
          err.message
        );
      }
    );
  }
);

// ===============================
// START SERVER
// ===============================

async function startServer() {

  try {

    await pool.query(
      "SELECT NOW()"
    );

    console.log(
      "PostgreSQL connected."
    );

    await createTables();

    await migrateOldUsers();

    // Initial market update
    await updateAllPrices();

    /*
     * Refresh market data every 60 seconds.
     * This is much faster than the old
     * 12 minute interval.
     */
    setInterval(
      updateAllPrices,
      60 * 1000
    );

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

  } catch (err) {

    console.error(
      "SERVER START ERROR:",
      err
    );

    process.exit(1);
  }
}

startServer();

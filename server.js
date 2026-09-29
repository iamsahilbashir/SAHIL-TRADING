const express = require("express");
const http = require("http");
const WebSocket = require("ws");
const { Pool } = require("pg");
const bcrypt = require("bcrypt");

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({
  server
});


/* =====================================================
   ENVIRONMENT
===================================================== */

const PORT =
  process.env.PORT || 10000;

const DATABASE_URL =
  process.env.DATABASE_URL;

const TWELVE_DATA_API_KEY =
  process.env.TWELVE_DATA_API_KEY;


/* =====================================================
   POSTGRESQL
===================================================== */

const pool =
  new Pool({
    connectionString:
      DATABASE_URL,

    ssl:
      process.env.NODE_ENV === "production"
        ? {
            rejectUnauthorized: false
          }
        : false
  });


/* =====================================================
   EXPRESS
===================================================== */

app.use(
  express.json({
    limit: "2mb"
  })
);

app.use(
  express.urlencoded({
    extended: true
  })
);


/* =====================================================
   SIMPLE SESSION STORE
===================================================== */

const sessions =
  new Map();


function createSession(userId) {

  const token =
    require("crypto")
      .randomBytes(32)
      .toString("hex");

  sessions.set(
    token,
    {
      userId,
      createdAt: Date.now()
    }
  );

  return token;
}


function getSession(req) {

  const header =
    req.headers.authorization;

  if (
    header &&
    header.startsWith("Bearer ")
  ) {

    const token =
      header.slice(7);

    return sessions.get(token);

  }


  const cookie =
    req.headers.cookie || "";

  const match =
    cookie.match(
      /sahil_session=([^;]+)/
    );

  if (!match)
    return null;


  return sessions.get(
    match[1]
  );
}


function setSessionCookie(
  res,
  token
) {

  res.setHeader(
    "Set-Cookie",
    [
      "sahil_session=" +
        token +
        "; Path=/; HttpOnly; SameSite=Lax"
    ]
  );

}


function clearSessionCookie(res) {

  res.setHeader(
    "Set-Cookie",
    [
      "sahil_session=; Path=/; HttpOnly; Max-Age=0; SameSite=Lax"
    ]
  );

}


async function requireAuth(
  req,
  res,
  next
) {

  try {

    const session =
      getSession(req);

    if (!session) {

      return res
        .status(401)
        .json({
          error:
            "Not authenticated."
        });

    }


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
        WHERE id=$1
        `,
        [
          session.userId
        ]
      );


    if (!result.rows.length) {

      return res
        .status(401)
        .json({
          error:
            "User not found."
        });

    }


    req.user =
      result.rows[0];

    req.userId =
      session.userId;


    next();

  } catch (error) {

    console.error(
      "Auth middleware error:",
      error
    );

    res
      .status(500)
      .json({
        error:
          "Authentication error."
      });

  }

}


/* =====================================================
   DATABASE SETUP
===================================================== */

async function setupDatabase() {

  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (

      id SERIAL PRIMARY KEY,

      name TEXT NOT NULL,

      email TEXT UNIQUE NOT NULL,

      password TEXT NOT NULL,

      balance DOUBLE PRECISION
        NOT NULL DEFAULT 10000,

      positions JSONB
        NOT NULL DEFAULT '[]'::jsonb,

      history JSONB
        NOT NULL DEFAULT '[]'::jsonb,

      watchlist JSONB
        NOT NULL DEFAULT '[]'::jsonb,

      notes TEXT
        NOT NULL DEFAULT '',

      created_at TIMESTAMP
        NOT NULL DEFAULT NOW()

    );
  `);


  console.log(
    "PostgreSQL tables ready"
  );

}


/* =====================================================
   HEALTH
===================================================== */

app.get(
  "/health",
  async (req, res) => {

    try {

      await pool.query(
        "SELECT 1"
      );

      res.json({
        ok: true
      });

    } catch (error) {

      res
        .status(500)
        .json({
          ok: false
        });

    }

  }
);


/* =====================================================
   SIGNUP
===================================================== */

app.post(
  "/api/signup",
  async (req, res) => {

    try {

      const name =
        String(
          req.body.name || ""
        ).trim();

      const email =
        String(
          req.body.email || ""
        )
        .trim()
        .toLowerCase();

      const password =
        String(
          req.body.password || ""
        );


      if (
        !name ||
        !email ||
        !password
      ) {

        return res
          .status(400)
          .json({
            error:
              "Name, email and password are required."
          });

      }


      if (
        password.length < 6
      ) {

        return res
          .status(400)
          .json({
            error:
              "Password must be at least 6 characters."
          });

      }


      const existing =
        await pool.query(
          `
          SELECT id
          FROM users
          WHERE email=$1
          `,
          [email]
        );


      if (
        existing.rows.length
      ) {

        return res
          .status(409)
          .json({
            error:
              "Email already registered."
          });

      }


      const hash =
        await bcrypt.hash(
          password,
          10
        );


      const defaultWatchlist = [
        "EUR/USD",
        "GBP/USD",
        "USD/JPY",
        "XAU/USD"
      ];


      const result =
        await pool.query(
          `
          INSERT INTO users
          (
            name,
            email,
            password,
            balance,
            positions,
            history,
            watchlist,
            notes
          )
          VALUES
          (
            $1,
            $2,
            $3,
            $4,
            $5,
            $6,
            $7,
            $8
          )
          RETURNING id
          `,
          [
            name,
            email,
            hash,
            10000,
            JSON.stringify([]),
            JSON.stringify([]),
            JSON.stringify(
              defaultWatchlist
            ),
            ""
          ]
        );


      const userId =
        result.rows[0].id;


      const token =
        createSession(
          userId
        );


      setSessionCookie(
        res,
        token
      );


      res.json({
        success: true
      });


    } catch (error) {

      console.error(
        "Signup error:",
        error
      );

      res
        .status(500)
        .json({
          error:
            "Signup failed."
        });

    }

  }
);


/* =====================================================
   LOGIN
===================================================== */

app.post(
  "/api/login",
  async (req, res) => {

    try {

      const email =
        String(
          req.body.email || ""
        )
        .trim()
        .toLowerCase();

      const password =
        String(
          req.body.password || ""
        );


      if (
        !email ||
        !password
      ) {

        return res
          .status(400)
          .json({
            error:
              "Email and password are required."
          });

      }


      const result =
        await pool.query(
          `
          SELECT *
          FROM users
          WHERE email=$1
          `,
          [email]
        );


      if (!result.rows.length) {

        return res
          .status(401)
          .json({
            error:
              "Invalid email or password."
          });

      }


      const user =
        result.rows[0];


      const valid =
        await bcrypt.compare(
          password,
          user.password
        );


      if (!valid) {

        return res
          .status(401)
          .json({
            error:
              "Invalid email or password."
          });

      }


      const token =
        createSession(
          user.id
        );


      setSessionCookie(
        res,
        token
      );


      res.json({
        success: true
      });


    } catch (error) {

      console.error(
        "Login error:",
        error
      );

      res
        .status(500)
        .json({
          error:
            "Login failed."
        });

    }

  }
);


/* =====================================================
   LOGOUT
===================================================== */

app.post(
  "/api/logout",
  (req, res) => {

    const cookie =
      req.headers.cookie || "";

    const match =
      cookie.match(
        /sahil_session=([^;]+)/
      );


    if (match) {

      sessions.delete(
        match[1]
      );

    }


    clearSessionCookie(
      res
    );


    res.json({
      success: true
    });

  }
);


/* =====================================================
   CURRENT USER / STATE
===================================================== */

app.get(
  "/api/me",
  async (req, res) => {

    try {

      const session =
        getSession(req);


      if (!session) {

        return res
          .status(401)
          .json({
            loggedIn: false
          });

      }


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
          WHERE id=$1
          `,
          [
            session.userId
          ]
        );


      if (!result.rows.length) {

        return res
          .status(401)
          .json({
            loggedIn: false
          });

      }


      const user =
        result.rows[0];


      res.json({

        loggedIn: true,

        user: {
          id: user.id,
          name: user.name,
          email: user.email
        },

        balance:
          Number(
            user.balance
          ),

        positions:
          Array.isArray(
            user.positions
          )
            ? user.positions
            : [],

        history:
          Array.isArray(
            user.history
          )
            ? user.history
            : [],

        watchlist:
          Array.isArray(
            user.watchlist
          )
            ? user.watchlist
            : [],

        notes:
          user.notes || ""

      });


    } catch (error) {

      console.error(
        "Me error:",
        error
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


/* =====================================================
   SAVE STATE
===================================================== */

app.post(
  "/api/state",
  requireAuth,
  async (req, res) => {

    try {

      const balance =
        Number(
          req.body.balance
        );


      const positions =
        Array.isArray(
          req.body.positions
        )
          ? req.body.positions
          : [];


      const history =
        Array.isArray(
          req.body.history
        )
          ? req.body.history
          : [];


      const watchlist =
        Array.isArray(
          req.body.watchlist
        )
          ? req.body.watchlist
          : [];


      const notes =
        typeof req.body.notes === "string"
          ? req.body.notes
          : "";


      await pool.query(
        `
        UPDATE users
        SET
          balance=$1,
          positions=$2,
          history=$3,
          watchlist=$4,
          notes=$5
        WHERE id=$6
        `,
        [
          Number.isFinite(balance)
            ? balance
            : 10000,

          JSON.stringify(
            positions
          ),

          JSON.stringify(
            history
          ),

          JSON.stringify(
            watchlist
          ),

          notes,

          req.userId
        ]
      );


      res.json({
        success: true
      });


    } catch (error) {

      console.error(
        "Save state error:",
        error
      );

      res
        .status(500)
        .json({
          error:
            "Unable to save state."
        });

    }

  }
);


/* =====================================================
   STATIC FRONTEND
===================================================== */

app.use(
  express.static(
    "public"
  )
);


/* =====================================================
   MARKET SYMBOLS
===================================================== */

const MARKET_SYMBOLS = [

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


/* =====================================================
   MARKET CACHE
===================================================== */

const latestQuotes = {};
const latestVolumes = {};
const latestChanges = {};
const latestPercentChanges = {};
const latestTimestamps = {};


/* =====================================================
   RATE LIMIT SAFE SETTINGS
===================================================== */

/*
  Your current Twelve Data limit:
  8 credits / minute.

  We therefore request maximum 8 symbols
  per API call.

  18 symbols are divided into:

  Batch 1 = 8
  Batch 2 = 8
  Batch 3 = 2

  We wait 70 seconds between batches.
*/

const BATCH_SIZE = 8;

const BATCH_INTERVAL =
  70 * 1000;

let marketBatchIndex = 0;


/* =====================================================
   NEXT BATCH
===================================================== */

function getNextMarketBatch() {

  const batch = [];


  for (
    let i = 0;
    i < BATCH_SIZE;
    i++
  ) {

    const index =
      (
        marketBatchIndex +
        i
      ) %
      MARKET_SYMBOLS.length;


    batch.push(
      MARKET_SYMBOLS[index]
    );

  }


  marketBatchIndex =
    (
      marketBatchIndex +
      BATCH_SIZE
    ) %
    MARKET_SYMBOLS.length;


  return batch;

}


/* =====================================================
   BROADCAST STATUS
===================================================== */

function broadcastStatus() {

  const message =
    JSON.stringify({

      type: "status",

      connected: true,

      symbols:
        MARKET_SYMBOLS.length,

      updatedAt:
        Date.now(),

      message:
        "Market connected"

    });


  wss.clients.forEach(
    client => {

      if (
        client.readyState ===
        WebSocket.OPEN
      ) {

        client.send(
          message
        );

      }

    }
  );

}


/* =====================================================
   BROADCAST MARKET
===================================================== */

function broadcastMarket(
  symbol,
  price,
  volume,
  change,
  percentChange,
  timestamp
) {

  const message =
    JSON.stringify({

      type: "market",

      data: {

        symbol,

        price,

        volume:
          volume === null ||
          volume === undefined ||
          volume === ""
            ? null
            : Number(volume),

        change:
          change === null ||
          change === undefined ||
          change === ""
            ? null
            : Number(change),

        percent_change:
          percentChange === null ||
          percentChange === undefined ||
          percentChange === ""
            ? null
            : Number(percentChange),

        timestamp:
          timestamp ||
          Date.now()

      }

    });


  wss.clients.forEach(
    client => {

      if (
        client.readyState ===
        WebSocket.OPEN
      ) {

        client.send(
          message
        );

      }

    }
  );

}


/* =====================================================
   BACKWARD COMPATIBILITY PRICE MESSAGE
===================================================== */

function broadcastOldPrice(
  symbol,
  price,
  volume
) {

  const message =
    JSON.stringify({

      type: "price",

      data: {

        symbol,

        price,

        volume:
          volume === undefined
            ? null
            : volume

      }

    });


  wss.clients.forEach(
    client => {

      if (
        client.readyState ===
        WebSocket.OPEN
      ) {

        client.send(
          message
        );

      }

    }
  );

}


/* =====================================================
   UPDATE ONE MARKET BATCH
===================================================== */

async function updateMarketBatch() {

  if (
    !TWELVE_DATA_API_KEY
  ) {

    console.log(
      "TWELVE_DATA_API_KEY is missing."
    );

    return;

  }


  const symbols =
    getNextMarketBatch();


  console.log(
    "Updating market batch:",
    symbols.join(", ")
  );


  try {

    /*
      Twelve Data batch quote request.
    */

    const url =
      "https://api.twelvedata.com/quote" +
      "?symbol=" +
      encodeURIComponent(
        symbols.join(",")
      ) +
      "&apikey=" +
      encodeURIComponent(
        TWELVE_DATA_API_KEY
      );


    const response =
      await fetch(
        url
      );


    const result =
      await response.json();


    /*
      If Twelve Data returns a
      global error.
    */

    if (
      result &&
      result.status === "error" &&
      !result[symbols[0]]
    ) {

      console.error(
        "Twelve Data error:",
        result
      );

      return;

    }


    /*
      Process each symbol.
    */

    for (
      const symbol of symbols
    ) {

      let data =
        result
          ? result[symbol]
          : null;


      /*
        Single-symbol fallback.
      */

      if (
        symbols.length === 1 &&
        result &&
        !result[symbol]
      ) {

        data = result;

      }


      if (
        !data ||
        data.status === "error"
      ) {

        console.log(
          "No market data:",
          symbol
        );

        continue;

      }


      const rawPrice =
        data.close ??
        data.price ??
        data.last;


      if (
        rawPrice === undefined ||
        rawPrice === null
      ) {

        console.log(
          "No price returned:",
          symbol
        );

        continue;

      }


      const price =
        Number(
          rawPrice
        );


      if (
        !Number.isFinite(price)
      ) {

        continue;

      }


      let volume = null;


      if (
        data.volume !== undefined &&
        data.volume !== null &&
        data.volume !== ""
      ) {

        const parsedVolume =
          Number(
            data.volume
          );


        if (
          Number.isFinite(
            parsedVolume
          )
        ) {

          volume =
            parsedVolume;

        }

      }


      const change =
        data.change ??
        null;


      const percentChange =
        data.percent_change ??
        null;


      const timestamp =
        data.timestamp ??
        Date.now();


      latestQuotes[symbol] =
        price;


      latestVolumes[symbol] =
        volume;


      latestChanges[symbol] =
        change;


      latestPercentChanges[symbol] =
        percentChange;


      latestTimestamps[symbol] =
        timestamp;


      console.log(
        symbol +
        " price: " +
        price +
        " volume: " +
        (
          volume === null
            ? "null"
            : volume
        )
      );


      broadcastMarket(
        symbol,
        price,
        volume,
        change,
        percentChange,
        timestamp
      );


      /*
        Keep the old message so
        existing HTML functionality
        continues working.
      */

      broadcastOldPrice(
        symbol,
        price,
        volume
      );

    }


    broadcastStatus();


    console.log(
      "Market batch complete."
    );


  } catch (error) {

    console.error(
      "Market update error:",
      error.message
    );

  }

}


/* =====================================================
   INITIAL MARKET UPDATE
===================================================== */

async function updateAllPrices() {

  console.log(
    "Updating market prices and volume..."
  );


  await updateMarketBatch();

}


/* =====================================================
   WEBSOCKET
===================================================== */

wss.on(
  "connection",
  ws => {

    console.log(
      "WebSocket client connected."
    );


    /*
      Send connection status.
    */

    ws.send(
      JSON.stringify({

        type: "status",

        connected: true,

        symbols:
          MARKET_SYMBOLS.length,

        updatedAt:
          Date.now(),

        message:
          "Market connected"

      })
    );


    /*
      Send cached prices immediately.
    */

    Object.keys(
      latestQuotes
    ).forEach(
      symbol => {

        const price =
          latestQuotes[
            symbol
          ];


        const volume =
          latestVolumes[
            symbol
          ] ??
          null;


        const change =
          latestChanges[
            symbol
          ] ??
          null;


        const percentChange =
          latestPercentChanges[
            symbol
          ] ??
          null;


        const timestamp =
          latestTimestamps[
            symbol
          ] ??
          Date.now();


        ws.send(
          JSON.stringify({

            type: "market",

            data: {

              symbol,

              price,

              volume,

              change,

              percent_change:
                percentChange,

              timestamp

            }

          })
        );


        /*
          Backward compatibility.
        */

        ws.send(
          JSON.stringify({

            type: "price",

            data: {

              symbol,

              price,

              volume

            }

          })
        );

      }
    );


    ws.on(
      "close",
      () => {

        console.log(
          "WebSocket client disconnected."
        );

      }
    );


    ws.on(
      "error",
      error => {

        console.error(
          "WebSocket error:",
          error.message
        );

      }
    );

  }
);


/* =====================================================
   RATE-LIMIT SAFE MARKET LOOP
===================================================== */

/*
  First update immediately.
*/

updateAllPrices();


/*
  Then update one batch every 70 seconds.

  18 symbols:
  8 + 8 + 2

  This keeps us below the
  8-credit/minute limit.
*/

setInterval(
  async () => {

    await updateMarketBatch();

  },
  BATCH_INTERVAL
);


/* =====================================================
   START SERVER
===================================================== */

async function startServer() {

  try {

    await pool.query(
      "SELECT NOW()"
    );


    console.log(
      "PostgreSQL connected"
    );


    await setupDatabase();


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


  } catch (error) {

    console.error(
      "Server startup error:",
      error
    );


    process.exit(
      1
    );

  }

}


startServer();


/* =====================================================
   ERROR HANDLERS
===================================================== */

process.on(
  "unhandledRejection",
  error => {

    console.error(
      "Unhandled rejection:",
      error
    );

  }
);


process.on(
  "uncaughtException",
  error => {

    console.error(
      "Uncaught exception:",
      error
    );

  }
);

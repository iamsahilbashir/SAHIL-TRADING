SAHIL TRADING PRO PLATFORM
Original trading platform inspired by common charting/trading workflows.

Included:
- Signup/login/logout
- Individual virtual demo account
- $10,000 starting balance
- Watchlist and symbol search
- Forex + XAU/USD
- TradingView-hosted interactive chart
- Timeframe/chart toolbar area
- Indicator/drawing/alert entry points
- Virtual BUY/SELL orders
- Lots, leverage UI, SL/TP fields
- Floating P/L, equity, positions and history
- User-specific saved state

IMPORTANT:
This is a demo trading platform, not a real broker and does not place real orders.
TradingView proprietary code/branding is not copied. The chart is an embedded TradingView widget.
For production use, review TradingView's current widget/license/attribution requirements.

SERVER:
Node.js backend required. GitHub Pages alone cannot run this project.
1. Copy .env.example to .env
2. Add Twelve Data API key and strong SESSION_SECRET
3. npm install
4. npm start

PRODUCTION HARDENING:
Use PostgreSQL/MySQL instead of users.json, HTTPS, secure production sessions,
rate limiting, CSRF protection, email verification/password reset, backups, monitoring,
and proper market-data licensing. Real-money trading would additionally require appropriate
brokerage infrastructure and applicable regulatory/compliance work.

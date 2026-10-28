// dev-server.js
// Local development server running Vercel serverless functions & static files
const http = require('http');
const fs = require('fs');
const path = require('path');
const url = require('url');

const PORT = process.env.PORT || 3000;
const PUBLIC_DIR = __dirname;

const authHandler = require('./api/auth');
const rewardsHandler = require('./api/rewards');
const redeemHandler = require('./api/redeem');
const statsHandler = require('./api/stats');
const auditHandler = require('./api/audit');
const pnlHandler = require('./api/pnl');

const routes = {
  '/api/auth': authHandler,
  '/api/rewards': rewardsHandler,
  '/api/redeem': redeemHandler,
  '/api/stats': statsHandler,
  '/api/audit': auditHandler,
  '/api/pnl': pnlHandler,
};

function parseCookies(req) {
  const list = {};
  const rc = req.headers.cookie;
  if (rc) {
    rc.split(';').forEach(cookie => {
      const parts = cookie.split('=');
      list[parts.shift().trim()] = decodeURI(parts.join('='));
    });
  }
  return list;
}

const server = http.createServer((req, res) => {
  const parsedUrl = url.parse(req.url, true);
  const pathname = parsedUrl.pathname;

  // Enhance request and response objects to mimic Vercel serverless environment
  req.query = parsedUrl.query;
  req.cookies = parseCookies(req);

  res.status = function (statusCode) {
    this.statusCode = statusCode;
    return this;
  };

  res.json = function (data) {
    this.setHeader('Content-Type', 'application/json');
    this.end(JSON.stringify(data));
    return this;
  };

  // Route API requests
  const apiHandler = routes[pathname];
  if (apiHandler) {
    let rawBody = '';
    req.on('data', chunk => {
      rawBody += chunk;
    });
    req.on('end', async () => {
      if (rawBody) {
        try {
          req.body = JSON.parse(rawBody);
        } catch {
          req.body = rawBody;
        }
      } else {
        req.body = {};
      }
      try {
        await apiHandler(req, res);
      } catch (err) {
        console.error('API Error:', err);
        if (!res.writableEnded) {
          res.status(500).json({ error: err.message || 'Internal Server Error' });
        }
      }
    });
    return;
  }

  // Static File Serving
  let filePath = path.join(PUBLIC_DIR, pathname === '/' ? 'index.html' : pathname);
  if (!fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) {
    filePath = path.join(PUBLIC_DIR, 'index.html');
  }

  const ext = path.extname(filePath).toLowerCase();
  const mimeTypes = {
    '.html': 'text/html; charset=utf-8',
    '.css': 'text/css',
    '.js': 'application/javascript',
    '.json': 'application/json',
    '.png': 'image/png',
    '.webp': 'image/webp',
    '.svg': 'image/svg+xml',
    '.txt': 'text/plain',
    '.xml': 'application/xml',
  };

  const contentType = mimeTypes[ext] || 'application/octet-stream';
  fs.readFile(filePath, (err, content) => {
    if (err) {
      res.writeHead(500);
      res.end('Server Error loading asset');
      return;
    }
    res.writeHead(200, {
      'Content-Type': contentType,
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
    });
    res.end(content);
  });
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`\n======================================================`);
  console.log(`🚀 LR Popcorn Club Local Server is live!`);
  console.log(`🔗 Local URL: http://localhost:${PORT}`);
  console.log(`✦ Customer View:  http://localhost:${PORT}`);
  console.log(`✦ Owner Portal:   http://localhost:${PORT}?page=owner`);
  console.log(`✦ Default Login:  owner / PopcornClub2026! or shankar / PopcornShankar2026!`);
  console.log(`======================================================\n`);
});

// Local development server: node server.js  ->  http://localhost:8000
// Needs a Postgres URL, e.g. (Windows CMD):  set DATABASE_URL=postgres://user:pass@host/db  &&  node server.js
const http = require('http');
const fs = require('fs');
const path = require('path');
const handler = require('./api/index.js');

const PORT = process.env.PORT || 8000;
http.createServer((req, res) => {
  if (req.url.startsWith('/api/')) return handler(req, res);
  if (req.url.split('?')[0] === '/') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(fs.readFileSync(path.join(__dirname, 'public', 'index.html')));
  }
  res.writeHead(404, { 'Content-Type': 'text/plain' });
  res.end('Not found');
}).listen(PORT, () => console.log('Campus Lost & Found is running at http://localhost:' + PORT));

// Local development server: node server.js  ->  http://localhost:8000
// Needs a Postgres URL, e.g. (Windows CMD):  set DATABASE_URL=postgres://user:pass@host/db  &&  node server.js
const http = require('http');
const handler = require('./api/index.js');

const PORT = process.env.PORT || 8000;
http.createServer((req, res) => handler(req, res)).listen(PORT, () => console.log('Campus Lost & Found is running at http://localhost:' + PORT));

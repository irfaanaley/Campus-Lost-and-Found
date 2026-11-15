CAMPUS LOST & FOUND (Node.js + Postgres)

FILES (all must be in the ROOT of your GitHub repo)
  api/index.js, public/index.html, package.json, vercel.json, server.js

DEPLOY LIVE ON VERCEL
  1. Delete ALL old files from the repo (app.py, web/, requirements.txt, old api/ and public/), then add the files above to the repo root.
  2. In Vercel > Project > Settings > General: set Framework Preset to "Other" and leave Root Directory / Output Directory / Build Command empty.
  3. Storage tab > Create/Connect Neon (Postgres) > Redeploy.
  4. Check: https://your-site.vercel.app/api/index?r=ping   (it should show "db": "ok")
  5. Open the site. The first person to fill in "Set up the owner account" becomes the Owner.

RUN LOCALLY (optional, needs Node 20+ and a Postgres URL, e.g. your Neon URL)
  1. npm install
  2. Windows CMD:  set DATABASE_URL=your-postgres-url  &&  node server.js
  3. Open http://localhost:8000

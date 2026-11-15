CAMPUS LOST & FOUND (Node.js + Postgres)

FILES (all must be in the ROOT of your GitHub repo)
  api/index.js, lib/page.js, public/index.html, package.json, vercel.json, server.js, build-page.js
  (The whole website is served by api/index.js, so lib/page.js and api/index.js are the important ones.)

DEPLOY LIVE ON VERCEL
  1. Delete ALL old files from the repo, then add the files above to the repo root (not inside a sub-folder).
  2. In Vercel: Framework Preset "Other"; leave Root Directory / Output Directory / Build Command empty.
  3. Storage tab > Create/Connect Neon (Postgres) > Redeploy.
  4. Check: https://your-site.vercel.app/api/index?r=ping   (it should show "db": "ok")
  5. Open the site. The first person to fill in "Set up the owner account" becomes the Owner.

EDITING THE WEBSITE
  Edit public/index.html, then run "node build-page.js" to update lib/page.js, and commit both.

RUN LOCALLY (optional, needs a current Node.js and a Postgres URL, e.g. your Neon URL)
  1. npm install
  2. Windows CMD:  set DATABASE_URL=your-postgres-url  &&  node server.js
  3. Open http://localhost:8000

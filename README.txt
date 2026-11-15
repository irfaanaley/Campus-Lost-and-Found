CAMPUS LOST & FOUND

RUN LOCALLY (for testing)
  1. pip install -r requirements.txt
  2. python api/index.py
  3. Open in your browser: http://localhost:8000
  (Locally the app automatically uses SQLite, so no Postgres is needed.)

DEPLOY LIVE ON VERCEL
  1. Put the contents of this folder (api, public, requirements.txt, vercel.json) in the ROOT of your GitHub repo.
     (The outer CampusLostFound folder itself must not be inside the repo.)
  2. In Vercel: Add New > Project > Import the GitHub repo > Deploy.
  3. Project > Storage tab > Create/Connect Neon (Postgres) > Redeploy.
  4. Check: https://your-site.vercel.app/api/index?r=ping   (it should show "db": "ok")
  5. Open the site. The first person to fill in "Set up the owner account" becomes the Owner.

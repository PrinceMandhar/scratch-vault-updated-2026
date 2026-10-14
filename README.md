# Scratch Vault (Netlify)
Links:
- Customer:  https://SITE.netlify.app/?t=TOKEN   (admin dashboard se har party ka alag link)
- Admin:     https://SITE.netlify.app/           (poora control)
- Team:      https://SITE.netlify.app/team       (sirf dekhna, koi change/download nahi)

Netlify > Environment variables (teeno zaroori):
- ADMIN_PASSWORD  = admin ka strong password
- TEAM_PASSWORD   = team ka alag password (admin se different)
- SESSION_SECRET  = 32+ random characters
Variables badalne ke baad dobara deploy karein.

200 fixed codes (2 Gold 1g, 5 Silver 20g, 193 Silver 10g) = netlify/functions/seed.mjs = scratch-card-200-codes.csv/xlsx.
Repo PRIVATE rakhein.

## Local test (VS Code)
Live Server sirf design dikhata hai, login/backend nahi chalta. Poora test:
1. `npm i -g netlify-cli` aur folder me `npm install`
2. `.env.example` ko copy karke `.env` banayein, passwords bharein
3. `netlify dev` chalayein -> http://localhost:8888 (admin) aur http://localhost:8888/team

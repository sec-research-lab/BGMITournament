# BGMI Tournament

## Live site (real backend, shared data)
https://bgmitournament.onrender.com/

Register, join tournaments, and check results there. Admin portal: `/admin.html`.

Free tier note: the service sleeps after ~15 min idle — the first request after a while can take 30-50s to wake up.

## Static demo (this repo's `index.html`)
[GitHub Pages](https://sec-research-lab.github.io/BGMITournament/) hosts a single-file, no-backend version of the same UI. Data there is stored in your browser's `localStorage` only — it is **not** shared between visitors or devices. Use it for a quick offline preview, not for a real tournament.

## Local development
```
npm install
npm start
```
Serves on `http://localhost:3000`.

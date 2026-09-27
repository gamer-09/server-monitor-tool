# server-monitor-tool (koi_12)

A lightweight Node.js + Express server monitor with a built-in web UI. It lists every
process listening on a TCP/UDP port of the host machine, applies simple heuristics to
flag suspicious listeners (clean / suspicious / virus), and lets you kill them by PID
or port.

## Features

- Lists all listening ports with process name, PID, protocol, and address (`GET /servers`)
- Heuristic threat scoring: encoded PowerShell, `wscript`/`cscript` running scripts,
  system binaries outside `system32`, executables in temp/downloads folders,
  commonly abused ports, random-looking executable names
- Web UI at `/ui` to inspect listeners and kill processes by selection or by port
- Optional admin token protection for kill requests (Bearer auth)
- Auto port fallback: if `PORT` is busy, the next free port is used

## Getting started

```bash
npm install
cp .env.example .env   # then set PORT / ADMIN_TOKEN as needed
npm run dev            # nodemon auto-reload
# or
npm start
```

Open `http://localhost:3000/ui` (or whichever port is logged to the console).

## Environment variables

All configuration lives in `.env` (loaded with `dotenv` by `server.js`).
`.env` is git-ignored — never commit real tokens.

| Variable       | Required | Description |
| -------------- | -------- | ----------- |
| `PORT`         | No       | Port to listen on (default `3000`; auto-increments if busy) |
| `ADMIN_TOKEN`  | No       | When set, kill requests require `Authorization: Bearer <ADMIN_TOKEN>`. When unset, kill requests are allowed from localhost only. |
| `GITHUB_TOKEN` | No       | Optional GitHub PAT for repo management tasks (e.g. updating the repo description via the GitHub API). Not used by the app at runtime. |

## API

| Method | Path            | Description                               |
| ------ | --------------- | ----------------------------------------- |
| GET    | `/healthz`      | Health check, returns `ok`                |
| GET    | `/`             | JSON service info (name, status, uptime)  |
| GET    | `/ui`           | Web UI                                    |
| GET    | `/servers`      | List listening servers with threat labels |
| POST   | `/servers/kill` | Kill by `pid` or `port`; auth as above    |

Example:

```bash
curl -X POST http://localhost:3000/servers/kill \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"port": 3000}'
```

## Security notes

- `.env`, `.env.*` (except `.env.example`), and token files like `Git_token.txt`
  are git-ignored — keep it that way.
- Set `ADMIN_TOKEN` whenever the server is reachable from other machines.
- If a token ever lands in a commit, a paste, or a screenshot, revoke and rotate it
  immediately at https://github.com/settings/tokens.

# LivePoll

A deliberately small, polished live polling tool. A signed-in host creates a poll, copies its URL, and every viewer sees vote totals change immediately—no refresh required.

## Stack and responsibilities

| Layer | What it does |
| --- | --- |
| React + Vite | Host dashboard, sign-in screens, share flow, voting UI, and an `EventSource` listener for live result changes. |
| Go + Gin | JSON API, JWT authentication, all input validation, voting rules, and the SSE endpoint. |
| MongoDB | Durable users, poll definitions, poll totals, and a uniquely indexed vote record to allow one vote per browser per poll. |
| Redis | The current result counts (`HASH`), Redis Pub/Sub fan-out for live events, and fast initial results for new viewers. |

Redis is intentionally in the voting path: after MongoDB accepts a unique vote, the API increments Redis's count hash and publishes the resulting tally. Every connected SSE client receives that publish and updates without polling or refreshing. MongoDB maintains a durable count so a Redis restart can be repopulated on the next poll read.

## Run locally

Requirements: Docker Desktop.

1. Copy `.env.example` to `.env` and set a long, random `JWT_SECRET`.
2. Run `docker compose up --build`.
3. Visit [http://localhost:8088](http://localhost:8088).

For frontend-only development, run `npm install && npm run dev` in `frontend/`, run the API/Mongo/Redis through Compose, and keep `CORS_ORIGINS=http://localhost:5173`.

## Deploy

The supplied Dockerfiles keep deployment platform-neutral. Create these four resources with your preferred host (Railway, Fly.io, Render, or a similar Docker host):

1. A MongoDB database; set its connection string as `MONGO_URI` and use `MONGO_DB=livepoll`.
2. A Redis service; set `REDIS_URL` to its complete connection URL. (The local Docker setup instead uses `REDIS_ADDR=redis:6379`.)
3. A backend Docker service from `backend/Dockerfile`; set `JWT_SECRET` to a long random value and `CORS_ORIGINS` to the frontend's final HTTPS URL.
4. A frontend Docker service from `frontend/Dockerfile`, building with `VITE_API_URL=https://YOUR-API.example.com/api`.

The frontend URL is the shareable live link. HTTPS is important: it enables reliable clipboard sharing and avoids browser restrictions around streaming connections.

## API overview

- `POST /api/auth/signup`, `POST /api/auth/login`
- `POST /api/polls` (JWT required), `GET /api/mine` (JWT required)
- `GET /api/polls/:id`, `POST /api/polls/:id/votes`
- `GET /api/polls/:id/events` (SSE)

Voters are anonymous by design. The browser receives a random UUID stored locally; the backend hashes it and uses a unique MongoDB index on `{pollId, voterKey}` to prevent repeat votes from that browser. This is a lightweight guard, not identity verification—authentication is specifically required for poll creation and management.

# IoT NAC Capstone

IoT Network Access Control (NAC) capstone project with a React frontend, NestJS backend, SQLite persistence, dynamic device discovery simulation, HMAC-based device identity, and policy enforcement workflows.

## Project Goals

- Persist device, identity, event, and enforcement state in SQLite
- Simulate dynamic discovery of IoT devices
- Verify device identity using signed heartbeats (HMAC)
- Apply allow/deny policy through an enforcement abstraction layer

## Current Feature Status

1. SQLite persistence: implemented
2. Dynamic discovery simulation: implemented
3. HMAC-based identity: in progress (implemented base flow + replay protection + lockout)
4. Enforcement abstraction layer: in progress (policy engine + adapter status + dry-run path)

## Monorepo Layout

- `backend/` NestJS API + SQLite + discovery + identity + enforcement
- `frontend/` React/Vite dashboard for device operations and telemetry
- `docs/` project docs/design notes

## Quick Start

### Prerequisites

- Node.js 20+
- npm

### 1) Start Backend

```bash
cd backend
npm install
npm run start:dev
```

Backend runs at `http://localhost:3000` by default.

### 2) Start Frontend

```bash
cd frontend
npm install
npm run dev
```

Frontend runs at `http://localhost:5173` by default and targets backend at `http://localhost:3000`.

## Important Backend Endpoints

- `GET /devices`
- `POST /devices/report`
- `GET /devices/:id/identity`
- `POST /devices/:id/identity/key`
- `POST /devices/:id/allow`
- `POST /devices/:id/deny`
- `GET /devices/:id/enforcement`
- `GET /events/recent`
- `GET /enforcement/status`
- `GET /audit`

## Testing and Validation

### Backend

```bash
cd backend
npm run lint
npm run test
npm run test:e2e
npm run build
```

### Frontend

```bash
cd frontend
npm run lint
npm run build
```

## Notes

- Main project documentation is this root `README.md`.
- `backend/README.md` and `frontend/README.md` are subproject-specific notes.

# NewSystem

NewSystem is an IAM-integrated agreement management system for MFU. It includes:

- Backend API for NewSystem registry records.
- Vue frontend for dashboard, NewSystem registry, account directory, settings, and permission management.
- IAM delegated authentication and permission filtering.
- Local/server Docker Compose files.
- GitLab CI and GitLab deploy compose templates for Harbor-based delivery.

## Runtime Ports

- Backend host port: `8095`
- Frontend host port: `8084`
- Production domain: `https://new-system.mfu.ac.th`

## Local Run

```bash
docker compose --env-file .env.local up -d --build
```

Open `http://127.0.0.1:8084`.

## Server Run

```bash
APP_ENV=prod ./server.sh deploy
```

The server compose binds backend and frontend to `127.0.0.1` by default so Nginx can publish the public domain.

## Backend Scripts

Run inside `backend-node`:

- `npm run start:local`
- `npm run test:contracts`
- `npm run bootstrap:permissions`
- `npm run reset:permissions`
- `npm run register:iam`

## Important

Real env files are present in this workspace and ignored by git. Do not commit secrets. Register the NewSystem IAM managed client before production login is expected to work end-to-end.

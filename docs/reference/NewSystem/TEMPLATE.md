# New System

Generated from the shared MFU IAM project template.

## IAM Setup

1. Review `backend-node/.env.local`, `.env.preprod`, and `.env.prod`.
2. Set `IAM_ADMIN_CLIENT_ID` and `IAM_ADMIN_CLIENT_SECRET` with an IAM admin B2B client.
3. Register the project B2B client:

```sh
cd backend-node
npm install
npm run register:iam:local
```

4. Bootstrap scoped Permission Matrix rows:

```sh
npm run bootstrap:iam:local
```

## Local Run

```sh
docker compose --env-file .env.local up -d --build
```

## Required IAM Permission Paths

- `/new-system/security/permission`
- `/dashboard`
- `/operations/business`
- `/management/category`
- `/config/message-authen`
- `/config/email-notifications`
- `/config/workflow-actions`
- `/config/runtime-access`
- `/config/database-backup`
- `/config/setting-message`
- `/config/verification`
- `/setting/group`
- `/setting/message-status`
- `/security/permissions/menu`
- `/security/permissions/group`
- `/security/permissions/matrix`
- `/security/audit`
- `/accounts/directory`
- `/accounts/lifecycle`

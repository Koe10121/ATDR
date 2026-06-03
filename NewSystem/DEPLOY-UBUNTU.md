# Ubuntu Server Deploy

ใช้ไฟล์นี้สำหรับ deploy `NewSystem` บน Ubuntu server ที่มี Docker และ Docker Compose plugin อยู่แล้ว

## ไฟล์ที่ใช้

- `docker-compose.server.yml`
- `.env.preprod` หรือ `.env.prod`
- `backend-node/.env.preprod` หรือ `backend-node/.env.prod`
- `server.sh`

## แนวทาง

- `local` ให้รันผ่าน `npm` ตรง ไม่ใช้ Docker
- `preprod` และ `prod` ให้รันผ่าน Docker Compose
- `frontend` รันผ่าน Nginx บนพอร์ต `80`
- `frontend` proxy `/api`, `/socket.io`, และ `/healthz` ไป `backend`
- `backend` default จะเปิดออก host แค่ `127.0.0.1:${BACKEND_PORT}`
- `redis` ไม่ publish port ออกภายนอก
- MongoDB ยังใช้ค่าจาก `backend-node/.env.preprod` หรือ `backend-node/.env.prod`

## เตรียมค่า

1. เลือก root env ให้ตรง environment:
   - `APP_ENV=preprod`
   - `APP_ENV=prod`
2. แก้ค่าอย่างน้อยใน `.env.preprod` หรือ `.env.prod`
   - `BASE_SERVER_URL`
   - `BACKEND_BIND_IP`
   - `GOOGLE_CLIENT_ID`
3. ตรวจ `backend-node/.env.preprod` หรือ `backend-node/.env.prod`
   - `MONGODB`
   - `IAM_SDK_BASE_URL`
   - `IAM_SDK_CLIENT_ID`
   - `IAM_SDK_CLIENT_SECRET`
4. ค่า `trust proxy`, `rate limit`, `browser/socket origins`, และ `allowed IPs`
   - จัดการผ่าน `Runtime Access Controls` ใน DB/CMS ที่ `/config/runtime-access`
   - ถ้า DB ยังไม่มี record ระบบจะ bootstrap จาก `NODE_ENV` และ `BASE_SERVER_URL`

## รัน

```bash
cd /path/to/NewSystem
APP_ENV=prod ./server.sh
```

## ตรวจสถานะ

```bash
./server.sh ps
curl -i http://127.0.0.1:${BACKEND_PORT:-8082}/healthz
```

## หยุดระบบ

```bash
./server.sh down
```

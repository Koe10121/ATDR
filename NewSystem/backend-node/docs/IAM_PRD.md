# Product Requirements Document (PRD)
## NewSystem IAM System — Backend Node.js

**Version:** 1.0  
**Date:** 2026-04-21  
**Status:** Current State Analysis  

---

## 1. Product Overview

### 1.1 วัตถุประสงค์
ระบบ IAM (Identity and Access Management) ของ NewSystem Backend ทำหน้าที่:
- ยืนยันตัวตนผู้ใช้งาน (Authentication)
- ควบคุมสิทธิ์การเข้าถึง (Authorization)
- จัดการวงจรชีวิตบัญชีผู้ใช้ (Account Lifecycle)
- บันทึกเหตุการณ์สำคัญ (Audit Logging)
- รองรับการเชื่อมต่อแบบ B2B สำหรับ NewSystem API

### 1.2 ขอบเขต (Scope)
ระบบครอบคลุม:
- NewSystem Backend API (`/api/v1/*`)
- การยืนยันตัวตนผ่าน Email/Password, Google SSO
- ระบบสิทธิ์ผ่าน IAM Service หรือ Local Database
- การจัดการ Group/Permission/Assignment
- ระบบ 2FA ผ่าน OTP Email
- Device Trust Management
- B2B Token Introspection

### 1.3 ผู้ใช้งาน (Users)
| ประเภท | คำอธิบาย | สิทธิ์ |
|--------|----------|--------|
| New System Admin | ผู้ดูแลระบบ NewSystem | org-wide access |
| NewSystem Manager | ผู้จัดการระดับ Unit | unit-level access |
| NewSystem Staff | พนักงานทั่วไป | self-level access |
| B2B Client | ระบบภายนอกที่เชื่อมต่อ | scoped API access |

---

## 2. Functional Requirements

### FR-01: Authentication

#### FR-01.1 Email/Password Login
- ระบบต้องรับ email + password ผ่าน `POST /api/v1/accounts/signin`
- ต้องตรวจสอบสถานะบัญชีเป็น `ACTIVE` ก่อนอนุญาตเข้าระบบ
- ต้องบันทึก Audit Event ทุกครั้งที่ sign-in

#### FR-01.2 Google SSO
- รองรับ Google ID Token ผ่าน `googleSub`
- ถ้าบัญชียังไม่มีในระบบ ต้องสร้างบัญชีใหม่อัตโนมัติ
- ต้องตรวจสอบ audience ของ Google Token

#### FR-01.3 Two-Factor Authentication (2FA)
- รองรับ OTP 6 หลัก ส่งผ่าน email
- OTP หมดอายุใน 5 นาที
- มี cooldown 30 วินาทีระหว่างการขอ OTP ใหม่
- สามารถบังคับ 2FA ทุก session ได้ผ่าน `PROJECT_AUTH_REQUIRE_2FA=true`

#### FR-01.4 Device Trust
- ผู้ใช้สามารถ mark device เป็น "trusted" ได้ (30 วันตาม `TRUST_DEVICE_DAYS`)
- Trusted device ข้าม 2FA ได้
- Device fingerprint = sha256(deviceId + userAgent)
- Network key = IP 3 octets แรก

#### FR-01.5 Session Management
- Session token เป็น random hex (ความยาวตาม `TOKEN_LENGTH`)
- เก็บใน `account.control.device[]`
- รองรับหลาย sessions พร้อมกัน (multi-device)
- รองรับ revoke session รายอุปกรณ์หรือทั้งหมด

### FR-02: Authorization

#### FR-02.1 Route-Level Permission
- ทุก protected route ต้องผ่าน `requirePermission(path, action)` middleware
- รองรับ actions: `view`, `edit`, `delete`, `action`, `logs`, `all`
- ตรวจสิทธิ์จาก IAM service (primary) หรือ local database (fallback)

#### FR-02.2 Permission Matrix
- Permission จัดเก็บระดับ Group-Menu
- User ได้รับ permissions จาก Groups ที่ assign อยู่
- Logic: OR — ถ้า group ใดก็ตาม grant action → ผ่าน

#### FR-02.3 Data Scope
- รองรับ 3 ระดับ: `self`, `unit`, `org`
- `self`: เข้าถึงข้อมูลตัวเองเท่านั้น
- `unit`: เข้าถึงข้อมูลใน Org Unit เดียวกัน
- `org`: เข้าถึงข้อมูลทั้งองค์กร

#### FR-02.4 NewSystem Scope Isolation
- Groups และ Menus ต้อง filter เฉพาะที่เป็น "New System Administration" type
- ป้องกันการเข้าถึงข้าม NewSystem scope

### FR-03: Account Management

#### FR-03.1 Account Lifecycle States
```
NEW → ACTIVE → INACTIVE → DEPROVISIONED
```
- `ACTIVE`: สามารถ sign-in ได้
- `INACTIVE`: ถูก disable โดย admin
- `DEPROVISIONED`: ถูก offboard ทุก session และ trusted device ถูกลบ

#### FR-03.2 Account Invitation
- Admin สามารถเชิญ user ใหม่ผ่าน email
- ถ้า user ยังไม่มีใน IAM ระบบต้อง invite ก่อน
- Sync group assignments ในขั้นตอนเดียว

#### FR-03.3 Lifecycle Management
- รองรับการอัพเดต affiliations, positions, access profiles
- รองรับหลาย org units

### FR-04: Security Administration

#### FR-04.1 Group Management
- CRUD สำหรับ Security Groups
- Groups มี title (multi-language), state, visibleType

#### FR-04.2 Permission Management
- CRUD สำหรับ Permissions (Group-Menu matrix)
- รองรับ bulk create/update

#### FR-04.3 Assignment Management
- CRUD สำหรับ Assignments (User-Group)
- กำหนด dataScope ต่อ assignment

#### FR-04.4 Bootstrap Access
- ระบบใหม่สร้าง default admin group อัตโนมัติ (idempotent)
- สร้าง default menus: dashboard, newSystem registry, security, audit, accounts
- เรียกครั้งแรกเมื่อ admin sign-in ครั้งแรก

### FR-05: Audit Logging

#### FR-05.1 Audit Events
- บันทึกทุก sensitive operation: signin, permission change, account status change
- เก็บ: module, action, actorId, resourceId, targetId, details, timestamp
- Queryable by module/action/actor/resource
- จำกัด limit: 50–200 records ต่อ query

#### FR-05.2 Retention
- ลบ Audit Log อัตโนมัติตาม `PROJECT_AUDIT_RETENTION_DAYS` (default 90 วัน)
- Archive ก่อนลบ

### FR-06: B2B Integration

#### FR-06.1 Token Introspection
- ตรวจสอบ Bearer token ผ่าน IAM `/introspect` endpoint
- ตรวจสอบ: active, audience, scope
- audience ต้องตรงกับ `IAM_B2B_REQUIRED_AUDIENCE`

#### FR-06.2 Scope Enforcement
- B2B endpoint แต่ละตัวต้องการ scope เฉพาะ
- ตรวจสอบผ่าน `requireScope(scope)` middleware

---

## 3. Non-Functional Requirements

### NFR-01: Security
- ทุก API endpoint ต้องผ่าน authentication middleware
- ต้องมี rate limiting (global: 100 req/15min)
- ต้องมี security headers (X-Content-Type-Options, X-XSS-Protection, X-Frame-Options)
- CORS ต้องตั้งค่าผ่าน config ไม่ใช่ wildcard

### NFR-02: Performance
- IAM API call timeout: 5,000ms
- Response caching สำหรับ static data ผ่าน Redis
- MongoDB indexes บน `{account, group}` สำหรับ Assignment

### NFR-03: Scalability
- รองรับ horizontal scaling (stateless sessions ผ่าน token)
- Redis สำหรับ shared cache

### NFR-04: Reliability
- Fallback จาก IAM → Local database ถ้า IAM ไม่พร้อมใช้งาน
- Audit logging failure ไม่ทำให้ main flow fail

### NFR-05: Maintainability
- Response format มาตรฐานทุก endpoint
- Multi-language สำหรับ user-facing text
- Configuration ผ่าน environment variables เท่านั้น

---

## 4. API Endpoints

### Authentication
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/v1/accounts/signin` | None | Sign in |
| POST | `/api/v1/accounts/signout` | Token | Sign out (current session) |
| POST | `/api/v1/accounts/signout/all` | Token | Sign out all sessions |
| POST | `/api/v1/accounts/auth/2fa/request` | Token | Request OTP |
| POST | `/api/v1/accounts/auth/2fa/verify` | Token | Verify OTP |
| POST | `/api/v1/accounts/auth/device/trust` | Token | Trust device |
| GET | `/api/v1/accounts/auth/device/trusted` | Token | List trusted devices |
| DELETE | `/api/v1/accounts/auth/device/trusted/:id` | Token | Revoke trusted device |

### Account Management
| Method | Path | Permission | Description |
|--------|------|------------|-------------|
| GET | `/api/v1/accounts` | accounts:view | List accounts |
| GET | `/api/v1/accounts/me` | None (self) | Current account info |
| GET | `/api/v1/accounts/:id` | accounts:view | Account detail |
| PUT | `/api/v1/accounts/:id` | accounts:edit | Update account |
| PUT | `/api/v1/accounts/:id/status` | accounts:action | Change status |

### Security Administration
| Method | Path | Permission | Description |
|--------|------|------------|-------------|
| GET/POST/PUT/DELETE | `/api/v1/security/type` | security:* | Type management |
| GET/POST/PUT/DELETE | `/api/v1/security/menu` | security:* | Menu management |
| GET/POST/PUT/DELETE | `/api/v1/security/group` | security:* | Group management |
| GET | `/api/v1/security/permission/my` | None | Own permissions |
| GET/POST/PUT/DELETE | `/api/v1/security/permission` | security:* | Permission management |
| GET/POST/PUT/DELETE | `/api/v1/security/assignment` | security:* | Assignment management |
| GET | `/api/v1/security/audit/events` | audit:logs | Audit log query |

---

## 5. Constraints and Assumptions

### Constraints
- ต้องพึ่งพา IAM Service สำหรับ permission ใน `iam` mode
- MongoDB เป็น primary database
- Node.js environment เท่านั้น

### Assumptions
- IAM Service ให้บริการ uptime สูงและ low latency
- Client ส่ง `x-access-token` header ทุก authenticated request
- B2B clients ใช้ OAuth2 Client Credentials Grant

---

## 6. Acceptance Criteria

| Feature | Criteria |
|---------|----------|
| Sign-in | สามารถ login ด้วย email/password และ Google SSO ได้ |
| 2FA | OTP ส่งทาง email ภายใน 30 วินาที, หมดอายุใน 5 นาที |
| Permission | ผู้ใช้ที่ไม่มีสิทธิ์ได้รับ 403 พร้อม denial reason |
| Data Scope | User ที่มี `self` scope ไม่สามารถเข้าถึงข้อมูลคนอื่นได้ |
| Audit | ทุก sign-in และ permission change ต้องมีใน audit log |
| Bootstrap | ระบบใหม่สร้าง admin group อัตโนมัติเมื่อ admin sign-in ครั้งแรก |
| Rate Limit | เกิน 100 req/15min ได้รับ 429 |

# IAM System Overview — NewSystem Backend Node.js

> เอกสารนี้สรุปสถาปัตยกรรม วิธีการทำงาน รูปแบบการเขียนโค้ด และข้อกำหนดของระบบ IAM ใน NewSystem Backend

---

## สารบัญ

1. [ภาพรวมระบบ](#1-ภาพรวมระบบ)
2. [สถาปัตยกรรม](#2-สถาปัตยกรรม)
3. [โมดูลและไฟล์สำคัญ](#3-โมดูลและไฟล์สำคัญ)
4. [Data Models](#4-data-models)
5. [API Flow](#5-api-flow)
6. [Scoping Model](#6-scoping-model)
7. [รูปแบบการเขียนโค้ด (Conventions)](#7-รูปแบบการเขียนโค้ด-conventions)
8. [การตั้งค่าระบบ (Configuration)](#8-การตั้งค่าระบบ-configuration)
9. [ข้อกำหนดระบบ (Requirements)](#9-ข้อกำหนดระบบ-requirements)

---

## 1. ภาพรวมระบบ

NewSystem Backend ใช้ระบบ IAM (Identity and Access Management) แบบ **Dual Permission Model** ซึ่งสามารถทำงานได้ 2 โหมด:

ค่ามาตรฐานของ backend ใช้ชื่อ env แบบ `PROJECT_*` และสำหรับ frontend ใช้ `VUE_APP_PROJECT_*`

| โหมด | ตัวแปร | คำอธิบาย |
|------|--------|----------|
| **IAM-First** (default) | `PROJECT_PERMISSION_SOURCE=iam` | ส่งต่อการตรวจสิทธิ์ไปยัง IAM Microservice ผ่าน SDK |
| **Local Fallback** | `PROJECT_PERMISSION_SOURCE=local` | ใช้ฐานข้อมูล MongoDB ของ NewSystem เอง |

### หน้าที่หลักของระบบ
- ยืนยันตัวตน (Authentication) ผ่าน IAM Service หรือ Google OAuth
- ควบคุมสิทธิ์การเข้าถึง (Authorization) ระดับ Path + Action
- จัดการ Group, Permission, Assignment
- บันทึก Audit Log
- รองรับ 2FA ผ่าน OTP Email
- รองรับ B2B Token สำหรับ NewSystem API

---

## 2. สถาปัตยกรรม

```
┌─────────────────────────────────────────────────────────┐
│                   NewSystem Backend                        │
│                                                          │
│  ┌──────────┐    ┌──────────────┐    ┌───────────────┐  │
│  │ Routes   │───>│  Middleware  │───>│  Controllers  │  │
│  │ /api/v1  │    │ Auth/Perm    │    │  (CRUD)       │  │
│  └──────────┘    └──────────────┘    └───────────────┘  │
│        │                │                   │           │
│        │          ┌─────▼──────┐     ┌──────▼──────┐   │
│        │          │authorization│    │  MongoDB     │   │
│        │          │.js          │    │  (Local DB)  │   │
│        │          └─────┬──────┘    └─────────────-┘   │
│        │                │                               │
│  ┌─────▼────────────────▼──────────────────────┐       │
│  │            IAM Admin Client                  │       │
│  │   (iam-admin-client.js + sdk.js)             │       │
│  └─────────────────────┬────────────────────────┘       │
└───────────────────────-│────────────────────────────────┘
                         │
                   ┌─────▼─────┐
                   │ IAM Service│
                   │ (External) │
                   └───────────┘
```

### Component หลัก

| Component | ไฟล์ | หน้าที่ |
|-----------|------|---------|
| IAM SDK | `server/integrations/iam/sdk.js` | Factory สร้าง SDK instance สำหรับ NewSystem |
| Authorization | `security/service/authorization.js` | HTTP Middleware ตรวจสิทธิ์ระดับ Route |
| Account Access | `security/service/account-access.js` | Permission Resolution Engine |
| IAM Admin Client | `security/service/iam-admin-client.js` | Proxy สำหรับ IAM Admin API |
| Bootstrap Access | `security/service/bootstrap-access.js` | สร้าง Default Admin สำหรับระบบใหม่ |
| Account Service | `accounts/service/account.js` | Authentication + Account Lifecycle |
| B2B Auth | `newSystem/service/newSystem_document.js` | ตรวจสอบ B2B Token สำหรับ NewSystem API |
| Audit | `security/service/audit.js` | อ่าน Audit Log |

---

## 3. โมดูลและไฟล์สำคัญ

### 3.1 Integration Layer

**`server/integrations/iam/sdk.js`**
- สร้าง NewSystem-configured IAM SDK instance ด้วย `createNewSystemSdk()`
- ใช้ clientId/clientSecret สำหรับ Admin access
- กำหนด Base URL, Token Endpoint, Admin Path, Introspection Path

### 3.2 Authorization Engine

**`security/service/authorization.js`**

ฟังก์ชัน: `requirePermission(paths, action, options)`

Flow:
1. Normalize permission path (ลบ query string, fragment, double slash)
2. เปรียบเทียบ singular/plural path (`/permission` vs `/permissions`)
3. เรียก `accountAccess.evaluatePermission()`
4. ถ้าไม่ผ่าน → return 401 หรือ 403 พร้อม denial reason
5. ถ้าผ่าน → บันทึกใน `request.permissionCheck` แล้ว next()

**`security/service/account-access.js`**

ฟังก์ชันหลัก:

| ฟังก์ชัน | คำอธิบาย |
|----------|----------|
| `evaluatePermission()` | ตรวจสิทธิ์หลัก |
| `getEffectivePermissions()` | สร้าง Permission Matrix ทั้งหมดของ account |
| `loadAssignmentsByAccountIds()` | โหลด assignments แบบ batch |
| `syncAccountAssignments()` | Sync assignments ระหว่าง local กับ IAM |
| `hasAssignmentScope()` | ตรวจ Data Scope |
| `collectAccountScopeKeys()` | ดึง Org/Unit keys สำหรับ scoping |

### 3.3 IAM Admin Client

**`security/service/iam-admin-client.js`**

ฟังก์ชันหลัก:

| ฟังก์ชัน | คำอธิบาย |
|----------|----------|
| `forwardAdminRequest()` | Generic proxy ไปยัง IAM Admin API |
| `forwardMyPermissions()` | ดึง Permission Matrix ของ user ปัจจุบัน |
| `forwardAccountsList()` | List accounts พร้อม NewSystem scope filter |
| `resolveScopedSecurityMetadata()` | กรอง Groups/Menus ตาม NewSystem scope |
| `inviteAccountToScope()` | เชิญ user ใหม่เข้า NewSystem scope |
| `syncAccountAssignments()` | Sync group memberships |
| `removeAccountFromScope()` | ปิดการเข้าถึง NewSystem ทั้งหมดของ account |

### 3.4 Account Service

**`accounts/service/account.js`**

Authentication Flow:
1. รับ email/password หรือ googleSub
2. ตรวจสอบ account status (ต้องเป็น ACTIVE)
3. ตรวจสอบ Trusted Device (ถ้า trusted → ข้าม 2FA)
4. สร้าง/เก็บ Session Token
5. เรียก Bootstrap Access ครั้งแรก
6. บันทึก Audit Event

ฟังก์ชันหลัก:

| ฟังก์ชัน | คำอธิบาย |
|----------|----------|
| `onCheckAuthorization()` | Middleware ดึง account จาก x-access-token |
| `SingIn()` | Login handler |
| `onTwoFaRequest()` | ส่ง OTP code ผ่าน email |
| `onTwoFaVerify()` | ตรวจสอบ OTP code |
| `onTrustDevice()` | Mark device ว่า trusted (30 วัน) |
| `onSessions()` / `onRevokeSession()` | จัดการ sessions |
| `onLogout()` / `onLogoutAll()` | ออกจากระบบ |
| `onUpdateLifecycle()` | อัพเดต Identity Provisioning state |
| `onProvisionAccount()` | Transition → PROVISIONED |
| `onDeprovisionAccount()` | Transition → DEPROVISIONED |

---

## 4. Data Models

### Assignment Model
```javascript
{
  account:    ObjectId,           // required
  group:      ObjectId,           // ref: Security_Group, required
  dataScope:  'self'|'unit'|'org', // default: 'self'
  scopeUnits: [String],           // สำหรับ unit scope
  active:     Boolean,            // default: true
  created:    { by, at },
  updated:    { by, at }
}
// Index: { account: 1, group: 1 } unique
```

### Group Model
```javascript
{
  title:       [{ key, value }],  // multi-language
  description: [{ key, value }],
  state:       Boolean,
  visibleType: ObjectId,          // ref: Security_Type
  created:     { by, at },
  updated:     { by, at }
}
```

### Permission Model
```javascript
{
  group:  ObjectId,   // ref: Security_Group, required
  menu:   ObjectId,   // ref: Security_Menu, required
  all:    Boolean,
  view:   Boolean,
  edit:   Boolean,
  delete: Boolean,
  action: Boolean,
  logs:   Boolean,
  created: { by, at },
  updated: { by, at }
}
// Index: { group: 1, menu: 1 } unique
```

### Menu Model
```javascript
{
  title:       [{ key, value }],
  description: [{ key, value }],
  state:       Boolean,
  path:        String,    // required, unique — e.g., '/dashboard'
  type:        ObjectId,  // ref: Security_Type, required
  created:     { by, at },
  updated:     { by, at }
}
```

### Audit Event Model
```javascript
{
  module:   String,   // e.g., 'accounts', 'security'
  action:   String,   // e.g., 'signin', 'permission.update'
  actor:    ObjectId, // ผู้กระทำ
  resource: ObjectId, // ทรัพยากรที่ถูกกระทำ
  target:   ObjectId,
  details:  Object,
  createdAt: Date
}
```

---

## 5. API Flow

### Authentication Flow (Sign-In)
```
Client → POST /api/v1/accounts/signin
  → account.SingIn()
    → ตรวจ email/password หรือ googleSub
    → ตรวจ account.status === 'ACTIVE'
    → สร้าง deviceFingerprint (sha256(deviceId + userAgent))
    → normalizeNetworkKey (IP 3 octets)
    → ตรวจ trustedDevice
    → ถ้าต้องการ 2FA: return { require2FA: true }
    → สร้าง session token (random hex)
    → เก็บใน account.control.device[]
    → เรียก bootstrapAccess (ครั้งแรก)
    → บันทึก Audit
  ← { token, accountInfo }
```

### Permission Check Flow
```
Client → GET /api/v1/newsystem/documents/...
  → onCheckAuthorization() → ดึง account จาก x-access-token
  → requirePermission('/newsystem/registry', 'view')
    → normalizePath('/newsystem/registry')
    → evaluatePermission(accountId, paths, action)
      → [IAM mode] GET /security/permission/my
      → [local mode] loadGroups → loadPermissions → buildMatrix
    → ตรวจสอบ matrix['/newsystem/registry']['view'] === true
  → ถ้าผ่าน: next()
  → ถ้าไม่ผ่าน: 403 { code: 40300, ... }
```

### B2B Token Flow
```
External System → POST /api/v1/newsystem/documents/...
  + Authorization: Bearer <token>
  → onCheckB2BAuthorization()
    → introspectToken() → IAM Service
    → ตรวจสอบ active, audience, scope
  → requireScope('new.system.registry.write')
    → ตรวจ token.scopes ประกอบด้วย 'new.system.registry.write'
  → ถ้าผ่าน: next()
```

---

## 6. Scoping Model

ระบบใช้ **3-Tier Data Scope** ผ่าน `assignment.dataScope`:

| Scope | คำอธิบาย | ใช้เมื่อ |
|-------|----------|---------|
| `self` | เข้าถึงข้อมูลตัวเองเท่านั้น | default สำหรับ user ทั่วไป |
| `unit` | เข้าถึงข้อมูลใน Org Unit เดียวกัน | หัวหน้าทีม/แผนก |
| `org` | เข้าถึงข้อมูลทั้งองค์กร | Admin ระดับสูง |

**Scope Keys** (ดึงจาก account HR context):
- `orgUnitCode`, `orgUnitName`
- `orgGroupName`, `subUnitName`

---

## 7. รูปแบบการเขียนโค้ด (Conventions)

### Error Codes
| Code | ความหมาย |
|------|----------|
| `40100` | Unauthorized (missing/invalid token) |
| `40300` | Forbidden (insufficient permissions) |
| `40400` | Not Found |
| `50000` | Server Error |

### Response Format
```javascript
{
  status:  Boolean,
  code:    Number,
  message: String,
  data:    any
}
```

### Middleware Pattern
```javascript
exports.functionName = async (request, response, next) => {
  try {
    // 1. ตรวจสอบ required fields
    // 2. Query database หรือ call IAM
    // 3. Format response ด้วย resMsg.onMessage_Response()
    return response.status(200).json(resData);
  } catch (err) {
    var resData = await resMsg.onMessage_Response(0, 50000);
    return response.status(500).json(resData);
  }
};
```

### IAM Fallback Pattern
```javascript
if (useIamPermissionSource()) {
  // ใช้ IAM service
} else {
  // ใช้ local database
}
// ทั้งสอง path return response format เดียวกัน
```

### Multi-Language
```javascript
// เก็บ text เป็น array
title: [{ key: 'en', value: 'Dashboard' }, { key: 'th', value: 'แดชบอร์ด' }]
// ใช้ helper
pickLangValue(title, 'en')
toLangArray({ en: 'Dashboard', th: 'แดชบอร์ด' })
```

### ObjectId Handling
```javascript
// ตรวจสอบก่อนใช้
if (!mongo.ObjectId.isValid(id)) throw new Error('Invalid ID');
// แปลงสำหรับ query
const oid = new mongo.ObjectId(id);
```

### Audit Logging
```javascript
await writeAudit({
  module:   'accounts',
  action:   'signin',
  actorId:  accountId,
  resource: accountId,
  details:  { channel: 'email' }
}, request);
```

---

## 8. การตั้งค่าระบบ (Configuration)

### ตัวแปรสภาพแวดล้อม (Environment Variables)

| ตัวแปร | ค่าตัวอย่าง | คำอธิบาย |
|--------|------------|----------|
| `MONGODB` | `mongodb://...` | MongoDB connection string |
| `PORT` | `3000` | Port ของ server |
| `KEY` | `<strong-key>` | Encryption key |
| `IAM_SDK_BASE_URL` | `http://iam:4000` | URL ของ IAM service |
| `IAM_SDK_CLIENT_ID` | `new-system-api` | Client ID สำหรับ IAM |
| `IAM_SDK_CLIENT_SECRET` | `<secret>` | Client Secret สำหรับ IAM |
| `PROJECT_PERMISSION_SOURCE` | `iam` / `local` | แหล่งข้อมูล permission |
| `PROJECT_PERMISSION_BOOTSTRAP_MODE` | `local` / `iam` / `disabled` | โหมด bootstrap |
| `PROJECT_PERMISSION_TYPE_TITLE` | `New System Administration` | ชื่อ type ใน IAM |
| `PROJECT_AUDIT_RETENTION_DAYS` | `90` | จำนวนวันเก็บ Audit Log |
| `PROJECT_AUTH_REQUIRE_2FA` | `true` / `false` | บังคับ 2FA |
| `TRUST_DEVICE_DAYS` | `30` | จำนวนวัน trusted device |
| `GOOGLE_CLIENT_ID` | `<google-client-id>` | Google OAuth Client ID |

### IAM Admin Scopes ที่ต้องการ
```
new.system.registry.read new.system.registry.write new.system.report.read
iam.security.read iam.security.write
iam.audit.read iam.accounts.read
```

---

## 9. ข้อกำหนดระบบ (Requirements)

### Runtime
- Node.js >= 16
- MongoDB >= 5.0
- Redis (สำหรับ cache middleware)
- IAM Service (สำหรับ IAM mode)

### Dependencies หลัก
- `express` — HTTP framework
- `mongoose` — MongoDB ODM
- `axios` — HTTP client สำหรับ IAM calls
- `redis` — Session/cache storage
- `google-auth-library` — Google OAuth verification
- `express-rate-limit` — Rate limiting
- `helmet` / `nocache` / security middlewares

### Middleware Stack (ลำดับ)
1. Rate limiter + block
2. Security headers (nocache, nosniff, xss-filter, ienoopen)
3. CORS (dynamic config)
4. Compression (gzip)
5. Logging (Morgan)
6. JSON/URL-encoded parsing (max 10MB)
7. express-validator

### Permission Actions
| Action | คำอธิบาย |
|--------|----------|
| `view` | อ่าน/ดูข้อมูล |
| `edit` | แก้ไขข้อมูล |
| `delete` | ลบข้อมูล |
| `action` | กระทำการพิเศษ (อนุมัติ ฯลฯ) |
| `logs` | ดู audit/activity logs |
| `all` | ทุก action |

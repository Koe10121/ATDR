# คำแนะนำการพัฒนาและปรับปรุง IAM System
## NewSystem Backend Node.js

**วันที่:** 2026-04-21  
**ระดับความสำคัญ:** Critical → High → Medium → Low

---

## สรุปภาพรวม

หลังจากวิเคราะห์ codebase พบว่าระบบมีพื้นฐานที่ดีในด้านสถาปัตยกรรมและการแยก concern แต่มีจุดที่ต้องแก้ไขเร่งด่วนในด้านความปลอดภัยและ code quality

---

## ระดับ CRITICAL — ต้องแก้ก่อน Deploy Production

### REC-C01: ย้าย Secrets ออกจาก .env และ Source Code

**ปัญหา:** Secrets หลายรายการถูก hardcode ใน `.env` และ source code
```
KEY="center"                         # encryption key ที่อ่อนแอมาก
IAM_SDK_CLIENT_SECRET=2e5a...        # API secret ใน version control
GOOGLE_CLIENT_ID=225788...           # ใน account.js line 166 (fallback)
```

**สิ่งที่ควรทำ:**
1. ย้าย secrets ทั้งหมดไปยัง Secret Manager (AWS Secrets Manager / HashiCorp Vault / GCP Secret Manager)
2. ลบ `.env` ออกจาก version control และเพิ่มใน `.gitignore`
3. ลบ fallback hardcoded Google Client ID ใน `account.js:166` ออก
4. เก็บค่า production ใน secret manager หรือ env จริงบน server เท่านั้น

```javascript
// BEFORE (account.js:164-166)
const audience =
    process.env.GOOGLE_CLIENT_ID ||
    process.env.VUE_APP_CLIENTID ||
    '225788483142-8pkg8on8nh60ao83ve33ff3lflv2ccvo.apps.googleusercontent.com'; // ลบออก

// AFTER
const audience = process.env.GOOGLE_CLIENT_ID;
if (!audience) throw new Error('GOOGLE_CLIENT_ID is required');
```

---

### REC-C02: แทน Deprecated Cryptography

**ปัญหา:** `helpers/utils.js` ใช้ `crypto.createCipher` และ `crypto.createDecipher` ที่ deprecated และไม่ใช้ IV/Salt

**สิ่งที่ควรทำ:**
```javascript
// BEFORE (utils.js) — Deprecated, no IV, no salt
exports.encrypt = function (data) {
    var cipher = crypto.createCipher('aes-256-cbc', key);
    ...
}

// AFTER — ใช้ createCipheriv พร้อม random IV
exports.encrypt = function (data) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(key, 'hex'), iv);
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return iv.toString('hex') + ':' + encrypted; // เก็บ IV ไว้ด้วย
};

exports.decrypt = function (data) {
    const [ivHex, encrypted] = data.split(':');
    const iv = Buffer.from(ivHex, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(key, 'hex'), iv);
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
};
```
- Key ต้องเป็น 32 bytes (256-bit) hex string
- ต้อง re-encrypt ข้อมูลที่เข้ารหัสด้วย method เดิม

---

### REC-C03: เพิ่ม Rate Limiting บน Authentication Endpoints

**ปัญหา:** `POST /signin` และ `POST /auth/2fa/verify` ไม่มี per-endpoint rate limiting

**สิ่งที่ควรทำ:**
```javascript
// config/rateLimit.js — เพิ่ม rate limiters เฉพาะ
const signinLimiter = rateLimit({
    windowMs: 5 * 60 * 1000,    // 5 นาที
    max: 5,                      // 5 ครั้งต่อ IP
    message: { code: 42900, message: 'Too many login attempts' }
});

const twoFaLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,   // 1 ชั่วโมง
    max: 3,                      // 3 ครั้งต่อ IP
    message: { code: 42900, message: 'Too many 2FA attempts' }
});

// accounts.routes.js
router.post('/signin', signinLimiter, account.SingIn);
router.post('/auth/2fa/verify', twoFaLimiter, account.onTwoFaVerify);
```

---

### REC-C04: เพิ่ม Attempt Limiting สำหรับ OTP Verification

**ปัญหา:** `onTwoFaVerify` ไม่มี attempt counter → brute-force OTP 6 หลักได้

**สิ่งที่ควรทำ:**
```javascript
// เพิ่ม verificationAttempts ใน verification record
const MAX_OTP_ATTEMPTS = 5;

const matched = account.verification.find(item => {
    if (!item || item.src !== 'signin-2fa') return false;
    if (item.attempts >= MAX_OTP_ATTEMPTS) return false; // ล็อค
    if (new Date(item.expired) < now) return false;
    return true;
});

// อัพเดต attempts เมื่อ fail
await Account.onUpdate(query, {
    $inc: { 'verification.$.attempts': 1 }
});
```

---

### REC-C05: เปิดใช้ HTTPS

**ปัญหา:** `server.js` ใช้ HTTP (TLS ถูก comment ออก)

**สิ่งที่ควรทำ:**
- ถ้า deploy ผ่าน Load Balancer/Reverse Proxy: เพิ่ม `trust proxy` และ redirect HTTP → HTTPS ที่ proxy layer
- ถ้า deploy โดยตรง: เปิดใช้ HTTPS certificate (Let's Encrypt)
- เพิ่ม HSTS header:
```javascript
app.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true }));
```

---

## ระดับ HIGH — ควรแก้ก่อน Production

### REC-H01: Hash Session Tokens ก่อนเก็บใน Database

**ปัญหา:** `xAccessToken` เก็บเป็น plaintext ใน MongoDB

**สิ่งที่ควรทำ:**
```javascript
// ก่อนเก็บ: hash token
const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
const devices = {
    xAccessToken: tokenHash,  // เก็บ hash ไม่ใช่ token จริง
    ...
};

// ก่อนตรวจสอบ: hash แล้วเปรียบเทียบ
const requestTokenHash = crypto.createHash('sha256').update(requestToken).digest('hex');
const session = account.control.device.find(d => d.xAccessToken === requestTokenHash);
```

---

### REC-H02: เพิ่ม Request ID / Correlation ID

**ปัญหา:** ไม่มี correlation ID ทำให้ trace incidents ยาก

**สิ่งที่ควรทำ:**
```javascript
// middleware/middlewares.js — เพิ่มก่อน middlewares อื่น
const { v4: uuidv4 } = require('uuid');

app.use((req, res, next) => {
    req.requestId = req.headers['x-request-id'] || uuidv4();
    res.setHeader('x-request-id', req.requestId);
    next();
});
```

---

### REC-H03: ปรับปรุง Error Responses ไม่ให้ Leak Internal Details

**ปัญหา:** `iam-admin-client.js:59-62` ส่ง error details กลับไปยัง client

**สิ่งที่ควรทำ:**
```javascript
// BEFORE
return response.status(502).json({
    error: 'iam_integration_failed',
    details: err && err.response ? err.response.data : err.message // leak!
});

// AFTER
console.error('[IAM Error]', { requestId: request.requestId, error: err.message });
return response.status(502).json({
    error: 'upstream_service_error',
    message: 'Unable to process request. Please try again later.'
});
```

---

### REC-H04: เพิ่ม Content-Security-Policy Header

**ปัญหา:** ไม่มี CSP header

**สิ่งที่ควรทำ:**
```javascript
// middleware/middlewares.js
const helmet = require('helmet');
app.use(helmet.contentSecurityPolicy({
    directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'"],
        imgSrc: ["'self'", 'data:'],
        connectSrc: ["'self'"],
        frameSrc: ["'none'"],
        objectSrc: ["'none'"],
    }
}));
```

---

### REC-H05: เพิ่ม CSRF Protection

**ปัญหา:** ไม่มี CSRF token บน state-changing operations

**สิ่งที่ควรทำ:**
- ถ้าใช้ SPA (token-based): ตรวจสอบ `Origin` และ `Referer` headers
- เพิ่ม `SameSite=Strict` บน cookies (ถ้าใช้ cookies)
- พิจารณาใช้ `csurf` package สำหรับ traditional web

---

### REC-H06: Session Cleanup Mechanism

**ปัญหา:** Sessions ไม่มี cleanup → document อาจโตเกิน MongoDB limit

**สิ่งที่ควรทำ:**
```javascript
// เพิ่ม cleanup ใน SingIn()
const MAX_SESSIONS_PER_USER = 10;
const SESSION_EXPIRY_DAYS = 30;

// ลบ sessions ที่หมดอายุ
await Account.onUpdate(query, {
    $pull: {
        'control.device': {
            expired_key: { $lt: Math.floor(Date.now() / 1000) }
        }
    }
});

// จำกัดจำนวน sessions
// ถ้า > MAX_SESSIONS_PER_USER ให้ลบที่เก่าที่สุด
```

---

### REC-H07: Input Validation บน Critical Endpoints

**ปัญหา:** ขาด input validation บาง endpoint

**สิ่งที่ควรทำ:**
```javascript
// เพิ่ม validation middleware
const { body, param } = require('express-validator');

router.post('/signin', [
    body('email').isEmail().normalizeEmail(),
    body('password').isLength({ min: 8, max: 128 }),
], validateRequest, account.SingIn);

router.get('/:id', [
    param('id').isMongoId(),
], validateRequest, account.onGet);
```

---

## ระดับ MEDIUM — ควรแก้ใน Sprint ถัดไป

### REC-M01: แก้ Race Condition ใน Device Trust

**ปัญหา:** `$pull` และ `$push` แยก operation → race condition

**สิ่งที่ควรทำ:**
```javascript
// ใช้ transaction หรือ atomic operation
await Account.onUpdate(query, {
    $set: {
        'control.device.$[elem]': updatedDevice
    }
}, {
    arrayFilters: [{ 'elem.fingerprint': fingerprint }]
});
```

---

### REC-M02: เพิ่ม Integrity Check บน Audit Logs

**ปัญหา:** Audit logs ไม่มี signature → แก้ไขย้อนหลังได้

**สิ่งที่ควรทำ:**
```javascript
// เพิ่ม checksum ใน audit event
const payload = JSON.stringify({ module, action, actorId, details, timestamp });
const checksum = crypto.createHmac('sha256', AUDIT_SECRET).update(payload).digest('hex');

await AuditEvent.create({ ...eventData, checksum });
```

---

### REC-M03: Implement Audit Log Alerting

**ปัญหา:** Audit logging ล้มเหลวแบบ silent

**สิ่งที่ควรทำ:**
```javascript
// helpers/audit.logger.js
async function writeAudit(payload = {}, request = null) {
    try {
        // ... สร้าง audit event
    } catch (err) {
        // ไม่ควร silent fail
        console.error('[AUDIT WRITE FAILED]', {
            requestId: request?.requestId,
            payload,
            error: err.message
        });
        // ส่ง alert ไปยัง monitoring system
        await alertMonitoring('audit_write_failure', { error: err.message });
    }
}
```

---

### REC-M04: จำกัด PII ใน Session Storage

**ปัญหา:** IP Address และ User-Agent เก็บแบบ plaintext ไม่จำกัดระยะเวลา

**สิ่งที่ควรทำ:**
- เปลี่ยนเก็บแค่ networkKey (IP 3 octets) แทน full IP
- กำหนด retention สำหรับ session data
- หรือ hash ข้อมูล PII ก่อนเก็บ

---

### REC-M05: เพิ่ม Monitoring และ Alerting

**สิ่งที่ควรทำ:**
- เพิ่ม metrics สำหรับ: failed logins, permission denials, 2FA failures
- ตั้ง alert เมื่อ: failed login rate สูงผิดปกติ, permission denial spike
- พิจารณาใช้ Prometheus + Grafana หรือ DataDog

---

### REC-M06: ปรับปรุง Bootstrap Mechanism

**ปัญหา:** Bootstrap ทำงานทุก sign-in แม้ admin เคย bootstrap แล้ว

**สิ่งที่ควรทำ:**
```javascript
// เช็ค flag ก่อน
const isBootstrapped = await BootstrapRecord.findOne({ accountId });
if (!isBootstrapped) {
    await ensureBootstrapAccessForAccount(accountId);
    await BootstrapRecord.create({ accountId, bootstrappedAt: new Date() });
}
```

---

## ระดับ LOW — ปรับปรุงเพิ่มเติม

### REC-L01: เปลี่ยนชื่อฟังก์ชัน `SingIn` → `signIn`

**ปัญหา:** Typo ใน `account.js` — `SingIn` แทนที่จะเป็น `signIn`

```javascript
// ใช้ rename refactoring tool เพื่อไม่ให้ miss references
```

---

### REC-L02: เพิ่ม JSDoc บน Public APIs

**สิ่งที่ควรทำ:**
```javascript
/**
 * ตรวจสอบสิทธิ์การเข้าถึง route
 * @param {string[]} paths - Permission paths ที่ต้องการ
 * @param {string} action - Action ที่ต้องการ (view/edit/delete/action/logs)
 * @param {Object} [options] - ตัวเลือกเพิ่มเติม
 * @param {Function} [options.targetAccountId] - Resolver สำหรับ scoped access
 */
exports.requirePermission = function(paths, action, options) { ... }
```

---

### REC-L03: เพิ่ม Health Check Endpoint

**สิ่งที่ควรทำ:**
```javascript
// server/routes/app.routes.js
app.get('/health', async (req, res) => {
    const health = {
        status: 'ok',
        timestamp: new Date().toISOString(),
        services: {
            mongodb: await checkMongoDB(),
            iam: await checkIAM(),
            redis: await checkRedis()
        }
    };
    res.json(health);
});
```

---

### REC-L04: เพิ่ม API Versioning Strategy

**สิ่งที่ควรทำ:**
- ปัจจุบันใช้ `/api/v1/*` แต่ไม่มีกลยุทธ์สำหรับ v2
- วางแผน deprecation strategy สำหรับ `/api/v1` ก่อน introduce `/api/v2`

---

### REC-L05: เพิ่ม Unit Tests Coverage

**ปัญหา:** มี test files น้อย (authorization.test.js, iam-admin-client.test.js, bootstrap-access.test.js)

**สิ่งที่ควรทำ:**
- เพิ่ม tests สำหรับ: account.js, account-access.js, audit.js
- Target: ≥ 80% coverage บน security-critical code
- เพิ่ม integration tests สำหรับ authentication flow

---

## สรุปลำดับความสำคัญ

| Priority | จำนวน | รายการ |
|----------|--------|--------|
| CRITICAL | 5 | REC-C01 ถึง REC-C05 |
| HIGH | 7 | REC-H01 ถึง REC-H07 |
| MEDIUM | 6 | REC-M01 ถึง REC-M06 |
| LOW | 5 | REC-L01 ถึง REC-L05 |

### Sprint แนะนำ

**Sprint 1 (URGENT — ก่อน Deploy Production):**
- REC-C01: ย้าย Secrets
- REC-C02: แทน Deprecated Crypto
- REC-C03: Rate Limiting Auth Endpoints
- REC-C04: OTP Attempt Limiting
- REC-C05: เปิดใช้ HTTPS

**Sprint 2:**
- REC-H01: Hash Session Tokens
- REC-H02: Request ID
- REC-H03: Error Response Cleanup
- REC-H05: CSRF Protection
- REC-H06: Session Cleanup

**Sprint 3:**
- REC-H04: CSP Header
- REC-H07: Input Validation
- REC-M01: Race Condition Fix
- REC-M02: Audit Integrity
- REC-M03: Audit Alerting

**Sprint 4+:**
- REC-M04 ถึง REC-L05

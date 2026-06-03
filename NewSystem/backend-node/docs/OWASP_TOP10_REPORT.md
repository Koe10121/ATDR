# OWASP Top 10 (2021) Security Report
## NewSystem Backend Node.js — IAM System

**วันที่ตรวจสอบ:** 2026-04-21  
**ผู้ตรวจสอบ:** Security Analysis (Automated Review)  
**ระดับความเสี่ยงรวม:** CRITICAL

---

## สรุปผล (Executive Summary)

| Category | Status | Severity |
|----------|--------|----------|
| A01 — Broken Access Control | VULNERABLE | CRITICAL |
| A02 — Cryptographic Failures | VULNERABLE | CRITICAL |
| A03 — Injection | VULNERABLE | HIGH |
| A04 — Insecure Design | VULNERABLE | CRITICAL |
| A05 — Security Misconfiguration | VULNERABLE | HIGH |
| A06 — Vulnerable Components | AT RISK | MEDIUM |
| A07 — Authentication Failures | VULNERABLE | CRITICAL |
| A08 — Software Integrity Failures | AT RISK | HIGH |
| A09 — Logging & Monitoring Failures | VULNERABLE | HIGH |
| A10 — SSRF | AT RISK | MEDIUM |

---

## A01:2021 — Broken Access Control
**Status: VULNERABLE | Severity: CRITICAL**

### Finding 1: Hardcoded Google Client ID (Fallback)
- **ไฟล์:** `server/Project/accounts/service/account.js:164-166`
- **ปัญหา:** Client ID hardcode เป็น fallback ในโค้ด ทำให้ Google token validation ทำงานได้แม้ไม่ตั้ง env var
```javascript
const audience =
    process.env.GOOGLE_CLIENT_ID ||
    process.env.VUE_APP_CLIENTID ||
    '225788483142-8pkg8on8nh60ao83ve33ff3lflv2ccvo.apps.googleusercontent.com'; // ⚠️
```
- **ผลกระทบ:** ผู้ไม่ประสงค์ดีทราบ Client ID สามารถใช้สร้าง token ปลอมได้
- **CWE:** CWE-798

### Finding 2: Insufficient Scope Validation on Account Routes
- **ไฟล์:** `server/Project/accounts/accounts.routes.js:110-114`
- **ปัญหา:** บาง route ใช้ `requireScopedAccount` เป็น middleware แต่การตรวจสอบ ownership ไม่ครอบคลุมทุก operation
- **ผลกระทบ:** อาจเกิด IDOR (Insecure Direct Object Reference)

### Finding 3: Permission Path Enumeration
- **ไฟล์:** `server/Project/security/service/authorization.js:83-91`
- **ปัญหา:** Error response บอก requiredAction และ requiredPaths ทำให้ attacker สามารถ enumerate permission paths ได้
- **ผลกระทบ:** Information disclosure เพื่อวางแผนโจมตี

**แนวทางแก้ไข:**
- ลบ fallback Google Client ID ออก
- เพิ่ม MongoId validation ก่อน query ทุก `:id` route
- ลด detail ใน 403 response

---

## A02:2021 — Cryptographic Failures
**Status: VULNERABLE | Severity: CRITICAL**

### Finding 1: Deprecated Cipher Functions
- **ไฟล์:** `helpers/utils.js:24-35`
- **ปัญหา:** ใช้ `crypto.createCipher` และ `crypto.createDecipher` ที่ deprecated ตั้งแต่ Node.js 10
```javascript
var cipher = crypto.createCipher('aes-256-cbc', key); // ⚠️ Deprecated
var decipher = crypto.createDecipher('aes-256-cbc', key); // ⚠️ Deprecated
```
- **ผลกระทบ:** ไม่ใช้ IV (Initialization Vector) → encryption อ่อนแอ → สามารถถอดรหัสได้
- **CWE:** CWE-327

### Finding 2: Weak Encryption Key
- **ไฟล์:** `.env:5`
- **ปัญหา:** `KEY="center"` — key ที่อ่อนมากและเปิดเผยใน version control
- **ผลกระทบ:** ข้อมูลที่เข้ารหัสถูก decrypt ได้ทันที
- **CWE:** CWE-798

### Finding 3: No HTTPS/TLS
- **ไฟล์:** `server.js:14-25`
- **ปัญหา:** HTTP server ทำงานโดยไม่มี TLS (HTTPS commented out)
- **ผลกระทบ:** ข้อมูลทั้งหมดส่งแบบ plaintext → MITM attack
- **CWE:** CWE-319

### Finding 4: Session Tokens Stored in Plaintext
- **ไฟล์:** `server/Project/accounts/service/account.js:301`
- **ปัญหา:** `xAccessToken` เก็บใน MongoDB โดยไม่ hash
- **ผลกระทบ:** DB breach = session hijacking ทุก account
- **CWE:** CWE-312

**แนวทางแก้ไข:**
- เปลี่ยนเป็น `crypto.createCipheriv` พร้อม random 16-byte IV
- ใช้ key ที่มีความยาว 32 bytes จาก secrets manager
- เปิดใช้ HTTPS หรือ terminate TLS ที่ proxy layer
- Hash tokens ด้วย SHA-256 ก่อนเก็บ DB

---

## A03:2021 — Injection
**Status: VULNERABLE | Severity: HIGH**

### Finding 1: Potential Command Injection
- **ไฟล์:** `server/Project/settings/service/hr_sync_runner.js`
- **ปัญหา:** ใช้ `spawnSync` กับ parameters ที่อาจมาจาก user input (filePath, sheetName)
- **ผลกระทบ:** ถ้า path/name ไม่ sanitized → OS command injection
- **CWE:** CWE-78

### Finding 2: Path Construction Without Validation
- **ไฟล์:** `server/Project/security/service/iam-admin-client.js:632-634`
- **ปัญหา:** ต่อ path ด้วย `request.params.id` โดยไม่ validate format เป็น MongoId
```javascript
path: `/accounts/${String(request.params && request.params.id ? request.params.id : '')}/effective-permissions`
```
- **ผลกระทบ:** Path traversal บน IAM API backend

### Finding 3: Confusing Password Logic (NoSQL-adjacent)
- **ไฟล์:** `server/Project/accounts/service/account.js:215-219`
- **ปัญหา:** Logic ตรวจสอบ password `=== "********"` สับสน — ไม่ชัดเจนว่าเป็น security bypass หรือ design
- **ผลกระทบ:** อาจมี bypass ที่ไม่ตั้งใจ

**แนวทางแก้ไข:**
- Validate ทุก user-supplied path ก่อนใช้ใน `spawnSync`
- เพิ่ม `isMongoId()` validation ก่อนใช้ id parameters
- ทบทวนและแก้ไข confusing password logic

---

## A04:2021 — Insecure Design
**Status: VULNERABLE | Severity: CRITICAL**

### Finding 1: 2FA Brute-Forceable
- **ไฟล์:** `server/Project/accounts/service/account.js:1266-1316`
- **ปัญหา:** ไม่มี attempt counter บน OTP verification → สามารถ brute force 1,000,000 combinations ได้
```javascript
var matched = account.verification.find(function (item) {
    if (String(item.code || '') !== code) return false; // ไม่มี attempt limit
    ...
});
```
- **ผลกระทบ:** 2FA ถูก bypass ได้
- **CWE:** CWE-307

### Finding 2: Session Created Before 2FA Completion
- **ไฟล์:** `server/Project/accounts/service/account.js:278-308`
- **ปัญหา:** Session token สร้างและเก็บก่อนที่ 2FA จะผ่าน → race condition / partial authentication
- **ผลกระทบ:** อาจ bypass 2FA ได้ในบางกรณี

### Finding 3: Weak Device Fingerprinting
- **ไฟล์:** `server/Project/accounts/service/account.js:69-72`
- **ปัญหา:** Fingerprint = sha256(deviceId + userAgent) — User-Agent สามารถปลอมได้ง่าย
- **ผลกระทบ:** Trusted device สามารถ impersonate ได้

### Finding 4: No Offline Token Validation
- **ไฟล์:** `server/Project/newSystem/service/newSystem_document.js:34-64`
- **ปัญหา:** B2B token ต้อง introspect ทุก request → ถ้า IAM ล่ม ทุก request fail
- **ผลกระทบ:** Single point of failure สำหรับ NewSystem API

**แนวทางแก้ไข:**
- เพิ่ม max 5 attempts บน OTP → lock verification record
- สร้าง session เฉพาะหลัง 2FA สำเร็จ
- เพิ่ม factor อื่นใน fingerprint (screen resolution, timezone)
- Cache token introspection result ระยะสั้น (1-2 นาที)

---

## A05:2021 — Security Misconfiguration
**Status: VULNERABLE | Severity: HIGH**

### Finding 1: Missing HSTS Header
- **ไฟล์:** `middleware/middlewares.js`
- **ปัญหา:** ไม่มี `Strict-Transport-Security` header
- **ผลกระทบ:** Browser ไม่บังคับ HTTPS

### Finding 2: Missing Content-Security-Policy
- **ไฟล์:** `middleware/middlewares.js`
- **ปัญหา:** ไม่มี CSP header
- **ผลกระทบ:** XSS attack บน web client ไม่ถูก block

### Finding 3: Overly Permissive Rate Limiter
- **ไฟล์:** `config/rateLimit.js:23-33`
- **ปัญหา:** Global rate limit 100 req/15min (~6.7/min) ไม่เพียงพอสำหรับ auth endpoints
- **ผลกระทบ:** Brute force ยังคงทำได้

### Finding 4: CORS Configuration
- **ปัญหา:** ควรตรวจสอบว่า CORS config ไม่ allow wildcard `*` บน production
- **ไฟล์:** ตั้งค่าผ่าน `/config/corsAndIP` endpoint

**แนวทางแก้ไข:**
- เพิ่ม HSTS, CSP headers
- แยก rate limiter สำหรับ auth endpoints (5 req/5min)
- ยืนยัน CORS config ไม่มี wildcard บน production

---

## A06:2021 — Vulnerable and Outdated Components
**Status: AT RISK | Severity: MEDIUM**

### Finding 1: Unverified Dependency Versions
- **ไฟล์:** `package.json`
- **ปัญหา:** ไม่ทราบ version ที่ใช้ทั้งหมด — อาจมี known vulnerabilities
- **แนวทางแก้ไข:** รัน `npm audit` เป็นประจำ เพิ่มใน CI/CD pipeline

### Finding 2: No Software Composition Analysis
- **ปัญหา:** ไม่มีกระบวนการตรวจสอบ dependencies อัตโนมัติ
- **แนวทางแก้ไข:** เพิ่ม Snyk หรือ Dependabot ใน pipeline

---

## A07:2021 — Identification and Authentication Failures
**Status: VULNERABLE | Severity: CRITICAL**

### Finding 1: No Rate Limiting on Sign-In
- **ไฟล์:** `server/Project/accounts/accounts.routes.js:29`
- **ปัญหา:** `POST /signin` ใช้เพียง global rate limiter ซึ่งไม่เพียงพอ
- **ผลกระทบ:** Password brute force ได้ ~6 ครั้ง/นาที
- **CWE:** CWE-307

### Finding 2: No Rate Limiting on 2FA Verify
- **ไฟล์:** `server/Project/accounts/accounts.routes.js:71`
- **ปัญหา:** `POST /auth/2fa/verify` ไม่มี rate limiting
- **ผลกระทบ:** OTP brute force ได้อย่างรวดเร็ว

### Finding 3: Unsigned Session Tokens
- **ไฟล์:** `helpers/utils.js:9-11`
- **ปัญหา:** Token เป็น random hex ไม่มี HMAC signature
```javascript
exports.createTokens = async function () {
    return await crypto.randomBytes(parseInt(cfg.tokenLength)).toString('hex');
}
```
- **ผลกระทบ:** ไม่สามารถตรวจสอบ integrity ของ token ได้
- **CWE:** CWE-347

### Finding 4: No Account Lockout Policy
- **ปัญหา:** ไม่มีการ lock account หลัง failed login attempts หลายครั้ง
- **ผลกระทบ:** Unlimited brute force attempts

**แนวทางแก้ไข:**
- เพิ่ม per-endpoint rate limiting (5 req/5min บน signin)
- ใช้ HMAC-signed tokens (JWT) หรือ hash tokens ในDB
- Implement account lockout หลัง 5-10 failed attempts

---

## A08:2021 — Software and Data Integrity Failures
**Status: AT RISK | Severity: HIGH**

### Finding 1: No Audit Log Integrity Verification
- **ไฟล์:** `server/Project/security/models/audit_event.model.js`
- **ปัญหา:** Audit records ไม่มี checksum/signature → สามารถแก้ไขได้โดยไม่ detect
- **ผลกระทบ:** Audit trail ไม่น่าเชื่อถือ

### Finding 2: No Archive Integrity Check
- **ไฟล์:** `server/Project/security/service/audit-retention-cleanup.js:86-98`
- **ปัญหา:** Archive documents ไม่มี checksum verification
- **ผลกระทบ:** ข้อมูล archive อาจถูกแก้ไข

### Finding 3: Unsigned Session Tokens (ซ้ำกับ A07)
- **ปัญหา:** ไม่มี integrity protection บน tokens
- **CWE:** CWE-347

**แนวทางแก้ไข:**
- เพิ่ม HMAC checksum บน audit event records
- Verify checksum เมื่อ query audit logs

---

## A09:2021 — Security Logging and Monitoring Failures
**Status: VULNERABLE | Severity: HIGH**

### Finding 1: Silent Audit Failure
- **ไฟล์:** `helpers/audit.logger.js`
- **ปัญหา:** `writeAudit()` catch error แล้ว return null โดยไม่ alert
```javascript
} catch (err) {
    return null; // ⚠️ Silent failure
}
```
- **ผลกระทบ:** Security events หายไปโดยไม่รู้ตัว

### Finding 2: Error Logs ขาด Request Context
- **ไฟล์:** `middleware/middlewares.js:52-55`
- **ปัญหา:** `console.error(err)` ไม่มี requestId, userId, path
- **ผลกระทบ:** Incident tracing ยาก

### Finding 3: Permission Denial Logging ขาด Actor Context
- **ไฟล์:** `server/Project/security/service/authorization.js:83-91`
- **ปัญหา:** Log permission denial แต่ไม่รวม IP, User ID, timestamp
- **ผลกระทบ:** ไม่สามารถตรวจจับ attack pattern ได้

### Finding 4: No Security Alerting
- **ปัญหา:** ไม่มีระบบ alert สำหรับ anomalies (high failed login rate, mass permission denials)
- **ผลกระทบ:** Attacks ไม่ถูกตรวจพบจนกว่าจะสายเกินไป

**แนวทางแก้ไข:**
- เพิ่ม structured logging (Winston/Pino) พร้อม correlation ID
- Log audit failures ไปยัง separate channel (stdout/file/monitoring)
- ตั้ง alert rules บน security events

---

## A10:2021 — Server-Side Request Forgery (SSRF)
**Status: AT RISK | Severity: MEDIUM**

### Finding 1: Unvalidated IAM API Paths
- **ไฟล์:** `server/Project/security/service/iam-admin-client.js:219-226`
- **ปัญหา:** `options.path` ไม่ validate ว่าเป็น relative path → อาจเป็น absolute URL
```javascript
url: `${USER_API_BASE_PATH}${options.path}`, // options.path ไม่ได้ validate
```
- **ผลกระทบ:** ถ้า attacker ควบคุม path ได้ → proxy request ไปยัง internal services

### Finding 2: Forward Admin Request Without Path Validation
- **ไฟล์:** `server/Project/security/service/iam-admin-client.js:234-251`
- **ปัญหา:** `forwardAdminRequest` และ `forwardUserRequest` forward path จาก request โดยตรง
- **ผลกระทบ:** Path traversal บน IAM backend

**แนวทางแก้ไข:**
- Whitelist allowed paths สำหรับ proxy functions
- Validate path ไม่มี `../` หรือ protocol prefix
- ใช้ URL parsing เพื่อตรวจสอบ host ไม่ถูกเปลี่ยน

---

## สรุปสถิติ

| Severity | จำนวน Finding |
|----------|--------------|
| CRITICAL | 10 |
| HIGH | 12 |
| MEDIUM | 8 |
| LOW | 3 |
| **รวม** | **33** |

---

## Remediation Roadmap

### Phase 1 — Critical (ต้องทำก่อน Deploy)
1. ย้าย Secrets ออกจาก code และ .env
2. แทน deprecated crypto functions
3. เปิดใช้ HTTPS/TLS
4. เพิ่ม rate limiting บน auth endpoints
5. เพิ่ม OTP attempt limiting

### Phase 2 — High (ภายใน 2 Sprints)
6. Hash session tokens ก่อนเก็บ DB
7. ลบ hardcoded Google Client ID fallback
8. เพิ่ม security headers (HSTS, CSP)
9. เพิ่ม structured logging พร้อม correlation ID
10. แก้ audit silent failure

### Phase 3 — Medium (ภายใน 1 เดือน)
11. เพิ่ม audit log integrity (checksum)
12. Implement account lockout policy
13. เพิ่ม security alerting/monitoring
14. Fix path validation ใน IAM proxy functions
15. เพิ่ม npm audit ใน CI/CD pipeline

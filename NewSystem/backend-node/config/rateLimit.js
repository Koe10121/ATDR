const rateLimit = require('express-rate-limit');
const runtimeAccessSettings = require('../helpers/runtime-access-settings');
const runtimeAccessMonitor = require('../helpers/runtime-access-monitor');
const RedisRateLimitStore = require('../helpers/redis-rate-limit-store');

const RATE_LIMIT_WINDOW_MS = 15 * 60 * 1000;
const rateLimitStore = new RedisRateLimitStore({
    windowMs: RATE_LIMIT_WINDOW_MS,
    prefix: process.env.RUNTIME_ACCESS_RATE_LIMIT_PREFIX || 'newSystem:runtime-access:rate-limit'
});

const limiter = rateLimit({
    windowMs: RATE_LIMIT_WINDOW_MS,
    max: 100,
    store: rateLimitStore,
    skip: function () {
        return !runtimeAccessSettings.isRateLimitEnabled();
    },
    handler: function (req, res) {
        runtimeAccessMonitor.blockIp(req.ip, RATE_LIMIT_WINDOW_MS, {
            source: 'rate-limit',
            reason: 'too-many-requests',
            method: req.method,
            path: req.originalUrl || req.url,
            origin: req.headers && req.headers.origin,
            statusCode: 429,
            message: 'Too many requests from this IP. You have been temporarily blocked.'
        });

        return res.status(429).json({
            message: 'Too many requests from this IP. You have been temporarily blocked.',
        });
    },
});

const blockMiddleware = async function (req, res, next) {
    try {
        if (!runtimeAccessSettings.isRateLimitEnabled()) {
            return next();
        }

        const blocked = await runtimeAccessMonitor.getBlockedIp(req.ip);
        if (!blocked) {
            return next();
        }

        runtimeAccessMonitor.recordEvent({
            source: 'rate-limit',
            type: 'blocked-ip-hit',
            decision: 'denied',
            ip: req.ip,
            method: req.method,
            path: req.originalUrl || req.url,
            origin: req.headers && req.headers.origin,
            statusCode: 403,
            message: 'Access denied. Your IP has been temporarily blocked.',
            detail: {
                expiresAt: blocked.expiresAt,
                remainingMs: blocked.remainingMs
            }
        });

        return res.status(403).json({
            message: 'Access denied. Your IP has been temporarily blocked.',
        });
    } catch (err) {
        return next(err);
    }
};

module.exports = { limiter, blockMiddleware };

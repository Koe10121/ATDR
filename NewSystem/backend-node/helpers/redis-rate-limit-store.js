'use strict';

const redisClient = require('./redis');

class RedisRateLimitStore {
    constructor(options) {
        const opts = options || {};
        this.windowMs = Number(opts.windowMs || 15 * 60 * 1000);
        this.prefix = String(opts.prefix || 'runtime-access:rate-limit');
        this.localKeys = false;
        this.fallback = new Map();
    }

    init(options) {
        if (options && options.windowMs) {
            this.windowMs = Number(options.windowMs);
        }
    }

    keyFor(key) {
        return `${this.prefix}:${key}`;
    }

    cleanupFallback(now) {
        this.fallback.forEach((record, key) => {
            if (!record || record.resetTime <= now) {
                this.fallback.delete(key);
            }
        });
    }

    incrementFallback(key) {
        const now = Date.now();
        this.cleanupFallback(now);
        const record = this.fallback.get(key);
        if (!record || record.resetTime <= now) {
            const fresh = { totalHits: 1, resetTime: now + this.windowMs };
            this.fallback.set(key, fresh);
            return { totalHits: fresh.totalHits, resetTime: new Date(fresh.resetTime) };
        }
        record.totalHits += 1;
        this.fallback.set(key, record);
        return { totalHits: record.totalHits, resetTime: new Date(record.resetTime) };
    }

    async increment(key) {
        if (redisClient.isReady()) {
            try {
                const result = await redisClient.incrementWindow(this.keyFor(key), this.windowMs);
                return {
                    totalHits: result.totalHits,
                    resetTime: new Date(result.resetTime)
                };
            } catch (error) {}
        }
        return this.incrementFallback(key);
    }

    async decrement(key) {
        if (redisClient.isReady()) {
            try {
                await redisClient.decrement(this.keyFor(key));
                return;
            } catch (error) {}
        }
        const record = this.fallback.get(key);
        if (!record) return;
        record.totalHits = Math.max(0, Number(record.totalHits || 0) - 1);
        if (record.totalHits <= 0) {
            this.fallback.delete(key);
            return;
        }
        this.fallback.set(key, record);
    }

    async resetKey(key) {
        if (redisClient.isReady()) {
            try {
                await redisClient.delete(this.keyFor(key));
            } catch (error) {}
        }
        this.fallback.delete(key);
    }

    async resetAll() {
        this.fallback.clear();
    }
}

module.exports = RedisRateLimitStore;

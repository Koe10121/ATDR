const redis = require("redis");

class RedisClient {
    constructor() {
        const redisUrl = process.env.REDIS_URL ? String(process.env.REDIS_URL).trim() : '';
        const redisHost = process.env.REDIS_HOST ? String(process.env.REDIS_HOST).trim() : '127.0.0.1';
        const redisPort = Number(process.env.REDIS_PORT || 6379);
        this.client = redis.createClient({
            url: redisUrl || undefined,
            socket: redisUrl ? undefined : { host: redisHost, port: redisPort }
        });
        this.connecting = null;
        this.connect();
    }

    async connect() {
        if (this.isReady()) {
            return this.client;
        }
        if (this.connecting) {
            return this.connecting;
        }
        this.connecting = this.client.connect()
            .then(() => {
                console.log("Redis connected");
                return this.client;
            })
            .catch((error) => {
                console.error("Redis connection failed:", error);
                return null;
            })
            .finally(() => {
                this.connecting = null;
            });
        return this.connecting;
    }

    isReady() {
        return !!(this.client && this.client.isOpen && this.client.isReady);
    }

    async get(key) {
        try {
            return await this.client.get(key);
        } catch (error) {
            console.error(`Error fetching key ${key} from Redis:`, error);
            return null;
        }
    }

    async setEx(key, ttl, value) {
        try {
            await this.client.setEx(key, ttl, value);
        } catch (error) {
            console.error(`Error setting key ${key} in Redis:`, error);
        }
    }

    async delete(key) {
        try {
            await this.client.del(key);
        } catch (error) {
            console.error(`Error deleting key ${key} from Redis:`, error);
        }
    }

    async incrementWindow(key, windowMs) {
        if (!this.isReady()) {
            throw new Error('redis_not_ready');
        }
        const result = await this.client.multi().incr(key).pTTL(key).exec();
        const totalHits = Number(Array.isArray(result) ? result[0] : 0);
        let ttlMs = Number(Array.isArray(result) ? result[1] : -1);
        if (!Number.isFinite(ttlMs) || ttlMs < 0) {
            await this.client.pExpire(key, windowMs);
            ttlMs = windowMs;
        }
        return {
            totalHits: totalHits,
            resetTime: Date.now() + ttlMs
        };
    }

    async decrement(key) {
        if (!this.isReady()) {
            return 0;
        }
        const value = Number(await this.client.decr(key));
        if (value <= 0) {
            await this.client.del(key);
        }
        return value;
    }
}

module.exports = new RedisClient();

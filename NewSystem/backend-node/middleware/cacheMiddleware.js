const redisClient = require("../helpers/redis");

exports.cacheMiddleware = async (req, res, next) => {
    const cacheKey = req.originalUrl || req.url; // ใช้ URL เป็น Key
    const cachedData = await redisClient.get(cacheKey);

    if (cachedData) {
        console.log("Cache Hit");
        return res.status(200).json(JSON.parse(cachedData));
    }

    // หากไม่มีใน Cache ให้ไปที่ Controller ต่อ
    req.cacheKey = cacheKey; // เก็บ Cache Key ใน Request Object เพื่อใช้ใน Controller
    next();
};

const winston = require('winston');
require('winston-mongodb');  // ต้อง require winston-mongodb
const mongoose = require('mongoose');

// สร้าง Logger สำหรับบันทึก log ลง MongoDB
const logger = winston.createLogger({
    level: 'info',  // กำหนดระดับความรุนแรงของ log
    format: winston.format.combine(
        winston.format.timestamp(),  // เก็บเวลาของ log
        winston.format.json()  // บันทึก log ในรูปแบบ JSON
    ),
    transports: [
        new winston.transports.MongoDB({
            db: process.env.LOG_MONGODB || process.env.MONGODB || 'mongodb://localhost:27017/logs',  // URL ของ MongoDB
            collection: 'logs',  // ชื่อ collection ที่จะเก็บ log
            level: 'info',  // กำหนดระดับ log ที่จะบันทึก (สามารถปรับให้เหมาะสมได้)
            storeHost: true,  // เก็บ hostname
            tryReconnect: true,  // ลองเชื่อมต่อใหม่หากการเชื่อมต่อ MongoDB ล้มเหลว
        })
    ]
});

// ฟังก์ชันสำหรับบันทึกข้อมูลที่เกี่ยวข้องกับ success
function logSuccessData(req, res, body) {
    const logData = {
        level: 'info',
        method: req.method,
        url: req.originalUrl,
        body: req.body,
        headers: req.headers,
        query: req.query,
        ip: req.ip,
        status: 'success',
        response: JSON.parse(JSON.stringify(body, null, 2)),
        statusCode: res.statusCode,
        timestamp: new Date() // เก็บ timestamp
    };

    logger.info(`Request Success: ${req.url}`, logData);
}

// ฟังก์ชันสำหรับบันทึกข้อมูลที่เกี่ยวข้องกับ error
function logErrorData(req, res, body) {
    const logData = {
        level: 'error',
        method: req.method,
        url: req.originalUrl,
        body: req.body,
        headers: req.headers,
        query: req.query,
        ip: req.ip,
        status: 'error',
        response: JSON.parse(JSON.stringify(body, null, 2)),
        statusCode: res.statusCode,
        timestamp: new Date() // เก็บ timestamp
    };

    logger.error(`Request Error: ${req.url}`, logData);
}

// ฟังก์ชันสำหรับลบ log เก่ากว่า 120 วัน (background)
async function deleteOldLogs() {
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - 120);  // ลบ log ที่เก่ากว่า 120 วัน

    try {
        // ลบ log ที่มีอายุมากกว่า 120 วัน
        await mongoose.connection.db.collection('logs').deleteMany({
            timestamp: { $lt: cutoffDate }
        });
        console.log('Old logs deleted successfully.');
    } catch (error) {
        console.error('Error deleting old logs:', error);
    }
}

// สร้าง middleware เพื่อดักจับข้อมูล response
function loggerMiddleware (req, res, next){
    const originalJson = res.json;
    const originalStatusJson = res.status().json;

    // ดักจับการส่ง json ปกติ (res.json())
    res.json = function (body) {
        res.locals.responseData = body;  // เก็บข้อมูล response ที่ส่งไปให้ client
        // บันทึก log ก่อนที่จะส่งข้อมูลไปยัง client
        if (res.statusCode >= 200 && res.statusCode < 400) {
            logSuccessData(req, res, body);
        } else {
            logErrorData(req, res, body);
        }
        return originalJson.call(this, body);  // เรียกใช้งาน res.json เดิม
    };

    // ดักจับการส่ง json เมื่อมีการกำหนด status (res.status().json())
    res.status().json = function (body) {
        res.locals.responseData = body;  // เก็บข้อมูล response ที่ส่งไปให้ client
        // บันทึก log ก่อนที่จะส่งข้อมูลไปยัง client
        if (res.statusCode >= 200 && res.statusCode < 400) {
            logSuccessData(req, res, body);
        } else {
            logErrorData(req, res, body);
        }
        return originalStatusJson.call(this, body);  // เรียกใช้งาน res.status().json เดิม
    };
    // ลบ log เก่าทุกๆ 10 วินาทีใน background
    // setTimeout(deleteOldLogs, 10000);

    next();
}

module.exports = loggerMiddleware ;

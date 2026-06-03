// middlewares/corsAndIP.js
const runtimeAccessSettings = require('../helpers/runtime-access-settings');
const runtimeAccessMonitor = require('../helpers/runtime-access-monitor');

const isProduction = process.env.NODE_ENV === 'production';

// การตั้งค่า CORS
const corsOptions = {
    origin: function (origin, callback) {
        if (!origin) {
            callback(null, true);
            return;
        }
        if (runtimeAccessSettings.isOriginAllowed(origin)) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
    allowedHeaders: ['X-Requested-With', 'Content-Type', 'Accept', 'Authorization', 'X-Access-Token', 'x-access-token', 'lang'],
    methods: ['POST', 'GET', 'PUT', 'DELETE', 'PATCH', 'OPTIONS']
};

// ฟังก์ชัน middleware สำหรับการตรวจสอบ IP ที่อนุญาต
const ipCheckMiddleware = (req, res, next) => {
    if (!isProduction) {
        return next();
    }
    const rawIP = req.ip || req.connection.remoteAddress || '';
    if (runtimeAccessSettings.isIpAllowed(rawIP)) {
        next();
    } else {
        runtimeAccessMonitor.recordEvent({
            source: 'ip-allow-list',
            type: 'ip-check',
            decision: 'denied',
            ip: rawIP,
            method: req.method,
            path: req.originalUrl || req.url,
            origin: req.headers && req.headers.origin,
            statusCode: 403,
            message: 'Access denied by runtime IP allow list.'
        });
        res.status(403).send('Access Denied');
    }
};

module.exports = { corsOptions, ipCheckMiddleware };

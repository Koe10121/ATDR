const express = require('express');
const nocache = require("nocache");
const nosniff = require("dont-sniff-mimetype");
const xssFilter = require("x-xss-protection");
const ienoopen = require("ienoopen");
const compression = require("compression");
const morgan = require("morgan");
const expressValidator = require('express-validator');
const rateLimit = require('express-rate-limit');
const path = require("path");
const cors = require('cors');

const { corsOptions, ipCheckMiddleware } = require('../config/corsAndIP');
const { limiter, blockMiddleware } = require('../config/rateLimit');
const runtimeAccessMonitor = require('../helpers/runtime-access-monitor');

// Import logger
const  loggerMiddleware  = require('../config/logger');

module.exports = function (app) {
    app.use(express.json({ limit: '10mb' }));
    app.use(express.urlencoded({ limit: '10mb', extended: true }));

    app.use(compression());
    app.use(cors(corsOptions));
    if (process.env.NODE_ENV === 'production') {

        app.use(blockMiddleware); // ตรวจสอบ IP ก่อน
        app.use(limiter); // ใช้ rate limiter หลังจากตรวจสอบ IP
        // การตรวจสอบ IP ที่อนุญาต
        app.use(ipCheckMiddleware);

        app.use(morgan('combined')); // ใช้ log format ที่เหมาะสม
    } else {
        app.use(morgan('dev')); // ใช้ log format สำหรับ development
    }

    // การใช้งาน logger ใน Express
    app.use(loggerMiddleware);

    app.use(expressValidator());
    app.disable("x-powered-by");
    app.use(ienoopen());
    app.use(nocache());
    app.use(nosniff());
    app.use(xssFilter());

    app.use(express.static(path.join(__dirname, "./public")));

    // Handle errors
    app.use((err, req, res, next) => {
        if (err && err.message === 'Not allowed by CORS') {
            runtimeAccessMonitor.recordEvent({
                source: 'http-cors',
                type: 'origin-check',
                decision: 'denied',
                ip: req.ip || (req.connection && req.connection.remoteAddress),
                method: req.method,
                path: req.originalUrl || req.url,
                origin: req.headers && req.headers.origin,
                statusCode: 403,
                message: 'Access denied by runtime browser origin policy.'
            });
            return res.status(403).send({ message: 'Not allowed by CORS' });
        }
        console.error(err);
        res.status(500).send({ message: "Internal Server Error" });
    });
};

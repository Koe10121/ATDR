var express = require('./config/express');
var app = express();
var http = require('http');
var https = require('https');
var fs = require('fs');
var cfg = require('./config/config');
var mongoose = require('mongoose');
var runtimeAccessSettings = require('./helpers/runtime-access-settings');
var runtimeAccessMonitor = require('./helpers/runtime-access-monitor');
/**
 * Get port from environment and store in Express.
 */


var port = cfg.host.port;

// var options = {
//     key : fs.readFileSync('/etc/letsencrypt/live/finnext.io/privkey.pem'),
//     cert : fs.readFileSync('/etc/letsencrypt/live/finnext.io/fullchain.pem'),
    // passphrase : cfg.passphrase
// };

/**
 * Create HTTP server.
 */

var server = http.createServer(app);
// var server = https.createServer(options, app);

/* Maintain a hash of all connected sockets */
// var sockets = {}, nextSocketId = 0;
// server.on('connection', function (socket) {
//     /* Add a newly connected socket */
//     var socketId = nextSocketId++;
//     //sockets[socketId] = socket;
//     //console.log('socket', socketId, 'opened');
//     /* Remove the socket when it closes */
//     socket.on('close', function () {
//         //console.log('socket', socketId, 'closed');
//         delete sockets[socketId];
//     });
//
//     /* Extend socket lifetime for demo purposes */
//     socket.setTimeout(cfg.timeout);
// });

var io = require('socket.io')(server,{
    cors: {
        origin: function (origin, callback) {
            if (runtimeAccessSettings.isSocketOriginAllowed(origin)) {
                callback(null, true);
            } else {
                runtimeAccessMonitor.recordEvent({
                    source: 'socket-cors',
                    type: 'origin-check',
                    decision: 'denied',
                    origin: origin,
                    statusCode: 403,
                    message: 'Access denied by runtime socket origin policy.'
                });
                callback(new Error('Not allowed by socket CORS'));
            }
        },
        credentials: true
    }})
require('./server/routes/socket.js')(io);



/**
 * Listen on provided port, on all network interfaces.
 */
//server.listen(port,hostip);
server.listen(port);
server.on('error', onError);
server.on('listening', onListening);


// Graceful shutdown function
let isShuttingDown = false;
const shutdown = () => {
    if (isShuttingDown) return;
    isShuttingDown = true;
    console.log('Gracefully shutting down...');

    // Stop accepting new requests
    server.close(async () => {
        console.log('Closed all HTTP connections');

        if (mongoose.connection && mongoose.connection.readyState !== 0) {
            await mongoose.connection.close();
            console.log('Closed MongoDB connection');
        }

        process.exit(0); // Exit process
    });

    // Force shutdown after 10 seconds if not finished
    setTimeout(() => {
        console.error('Forcing shutdown');
        process.exit(1); // Non-zero exit code for forced shutdown
    }, 10000).unref();
};

// Listen for termination signals (e.g., from Docker, Kubernetes, or Ctrl+C)
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);

/**
 * Event listener for HTTP server "error" event.
 */

function onError(error) {
    if (error.syscall !== 'listen') {
        throw error;
    }

    var bind = typeof port === 'string'
        ? 'Pipe ' + port
        : 'Port ' + port;

    // handle specific listen errors with friendly messages
    switch (error.code) {
        case 'EACCES':
            console.error(bind + ' requires elevated privileges');
            process.exit(1);
            break;
        case 'EADDRINUSE':
            console.error(bind + ' is already in use');
            process.exit(1);
            break;
        default:
            throw error;
    }
}

/**
 * Event listener for HTTP server "listening" event.
 */

function onListening() {
    var addr = server.address();
    var bind = typeof addr === 'string'
        ? 'pipe ' + addr
        : 'port ' + addr.port;
}

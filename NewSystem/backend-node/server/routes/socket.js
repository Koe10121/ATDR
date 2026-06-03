
module.exports = function(io) {


    io.on('connection', function(socket) {
        console.log('a user connected');
        socket.on('disconnect', () => {
            console.log('user disconnected');
        });
        socket.on('my message', (msg) => {
            console.log('message: ' + msg);
            io.emit('my broadcast', `server: ${msg}`);
        });
        // console.log(socket.handshake.headers);
        //
        // socket.on('message', async function (message) {
        //     console.log('info', message);
        //
        //
        //     //     console.log('from console',message.value);
        // });
        //
        // socket.on('campus', async function (message) {
        //     var querys = {};
        //     const doc = await Setting_Campus.onQuerys(querys);
        //     socket.emit('campus', doc);
        // });
        //
        // console.log('a user connected');
        // socket.on('disconnect', () => {
        //     console.log('user disconnected');
        // });

    });
};

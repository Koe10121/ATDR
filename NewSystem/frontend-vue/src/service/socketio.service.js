import { io } from 'socket.io-client';
class SocketioService {
    socket;
    constructor() {}

    setupSocketConnection() {
        const socketUrl = process.env.VUE_APP_SOCKET_URL ||
            (typeof window !== 'undefined' && window.location && window.location.hostname
                ? `http://${window.location.hostname}:8082`
                : 'http://127.0.0.1:8097');
        this.socket = socketUrl === 'same-origin' ? io() : io(socketUrl);
    }

    disconnect() {
        if (this.socket) {
            this.socket.disconnect();
        }
    }


// io.on('connection', (socket) => {
//     console.log('a user connected');
//
//     socket.on('disconnect', () => {
//         console.log('user disconnected');
//     });
//
//     socket.on('my message', (msg) => {
//         console.log('message: ' + msg);
//     });
// });

}



export default new SocketioService();

const http = require('http');
const fs = require('fs');
const path = require('path');

const port = Number(process.env.PORT || 80);
const rootDir = path.join(__dirname, 'dist');

const mimeTypes = {
  '.css': 'text/css; charset=utf-8',
  '.gif': 'image/gif',
  '.html': 'text/html; charset=utf-8',
  '.ico': 'image/x-icon',
  '.jpeg': 'image/jpeg',
  '.jpg': 'image/jpeg',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.map': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.svg': 'image/svg+xml',
  '.txt': 'text/plain; charset=utf-8',
  '.webp': 'image/webp',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2'
};

function sendFile(filePath, response) {
  fs.readFile(filePath, function (error, content) {
    if (error) {
      response.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' });
      response.end('Internal Server Error');
      return;
    }

    const extname = path.extname(filePath).toLowerCase();
    response.writeHead(200, {
      'Content-Type': mimeTypes[extname] || 'application/octet-stream',
      'Cache-Control': extname === '.html' ? 'no-cache' : 'public, max-age=31536000, immutable'
    });
    response.end(content);
  });
}

http.createServer(function (request, response) {
  const requestPath = decodeURIComponent((request.url || '/').split('?')[0]);
  const normalizedPath = path.normalize(requestPath).replace(/^(\.\.[/\\])+/, '');
  const targetPath = path.join(rootDir, normalizedPath);

  fs.stat(targetPath, function (error, stats) {
    if (!error && stats.isFile()) {
      sendFile(targetPath, response);
      return;
    }

    if (!error && stats.isDirectory()) {
      const indexPath = path.join(targetPath, 'index.html');
      fs.stat(indexPath, function (indexError, indexStats) {
        if (!indexError && indexStats.isFile()) {
          sendFile(indexPath, response);
          return;
        }

        sendFile(path.join(rootDir, 'index.html'), response);
      });
      return;
    }

    sendFile(path.join(rootDir, 'index.html'), response);
  });
}).listen(port, function () {
  console.log('Frontend server listening on port ' + port);
});

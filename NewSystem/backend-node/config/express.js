// app.js
const express = require('express');
const initialize = require("../helpers/initialize");
const middlewares = require('../middleware/middlewares');
const swagger = require('../swagger/swagger');
const routes = require('../server/routes/app.routes');
const { corsOptions } = require('./corsAndIP');
const runtimeAccessSettings = require('../helpers/runtime-access-settings');
const databaseBackup = require('../server/Project/settings/service/database_backup');

let isReady = false;

module.exports = function () {
  const app = express();
  runtimeAccessSettings.bindExpressApp(app);

  // Swagger setup
  swagger(app);

  app.get('/healthz', (req, res) => {
    if (isReady) {
      res.status(200).send('OK');
    } else {
      res.status(503).send('Service Unavailable');
    }
  });

  initialize.init(async function (status) {
    if (status) {
      await runtimeAccessSettings.prime();
      await databaseBackup.primeAutoBackup().catch((err) => {
        console.error('Database backup scheduler prime failed:', err && err.message ? err.message : err);
      });
      middlewares(app);
      app.options('*', require('cors')(corsOptions));

      // Load routes
      routes(app);
      isReady = true;
    }
  });

  return app;
};

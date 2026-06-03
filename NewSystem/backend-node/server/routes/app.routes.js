const accountRoutes = require("../Project/accounts/accounts.routes");
const newSystemRoutes = require("../Project/newSystem/newSystem.routes");
const securityRoutes = require("../Project/security/security.routes");
const settingsRoutes = require("../Project/settings/settings.routes");

module.exports = function (app) {
  const path = "/api/v1";

  app.use(path + '/newSystem', newSystemRoutes);
  app.use(path + '/setting', settingsRoutes);
  app.use(path + '/security', securityRoutes);
  app.use(path, accountRoutes);
};

'use strict';

const baseConfig = require('@vue/cli-plugin-e2e-nightwatch/nightwatch.config.js');

const chromedriverBinary = String(process.env.CHROMEDRIVER_BINARY || '').trim();

if (chromedriverBinary) {
  if (baseConfig.webdriver) {
    baseConfig.webdriver = Object.assign({}, baseConfig.webdriver, {
      server_path: chromedriverBinary
    });
  }

  if (baseConfig.selenium) {
    baseConfig.selenium = Object.assign({}, baseConfig.selenium, {
      cli_args: Object.assign({}, baseConfig.selenium.cli_args || {}, {
        'webdriver.chrome.driver': chromedriverBinary
      })
    });
  }
}

module.exports = baseConfig;

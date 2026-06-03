'use strict';

const path = require('path');
const { spawn } = require('child_process');
const { resolveChromedriverBinary } = require('../../../scripts/resolve-chromedriver');

const projectDir = path.resolve(__dirname, '..');

function resolveApiBaseUrl() {
  return String(process.env.VUE_APP_API_BASE_URL || 'http://127.0.0.1:18082').trim();
}

function resolvePort(apiBaseUrl) {
  try {
    const parsed = new URL(apiBaseUrl);
    return String(parsed.port || (parsed.protocol === 'https:' ? '443' : '80'));
  } catch (error) {
    return '18082';
  }
}

function resolveVueCliBin() {
  const basePath = path.resolve(projectDir, 'node_modules', '.bin', 'vue-cli-service');
  return process.platform === 'win32' ? `${basePath}.cmd` : basePath;
}

function parseArgs(argv) {
  const options = {
    headless: false,
    passthrough: [],
    test: ''
  };

  for (let index = 0; index < argv.length; index += 1) {
    const current = argv[index];
    if (current === '--headless') {
      options.headless = true;
      continue;
    }
    if (current === '--test' && argv[index + 1]) {
      options.test = String(argv[index + 1]);
      index += 1;
      continue;
    }
    options.passthrough.push(current);
  }

  return options;
}

async function run() {
  const apiBaseUrl = resolveApiBaseUrl();
  const mockApiPort = resolvePort(apiBaseUrl);
  const mockApiPath = path.resolve(projectDir, 'tests', 'e2e', 'mock-api.js');
  const vueCliBin = resolveVueCliBin();
  const runtimeArgs = parseArgs(process.argv.slice(2));

  const mockApi = spawn(process.execPath, [mockApiPath], {
    cwd: projectDir,
    env: Object.assign({}, process.env, {
      MOCK_API_PORT: mockApiPort
    }),
    stdio: ['ignore', 'pipe', 'pipe']
  });

  let settled = false;

  function cleanup(exitCode) {
    if (mockApi && !mockApi.killed) {
      mockApi.kill('SIGTERM');
    }
    process.exit(exitCode);
  }

  process.on('SIGINT', function () {
    cleanup(130);
  });

  process.on('SIGTERM', function () {
    cleanup(143);
  });

  mockApi.stderr.on('data', function (chunk) {
    process.stderr.write(chunk);
  });

  mockApi.on('exit', function (code) {
    if (!settled) {
      settled = true;
      console.error(`Mock API exited before tests started with code ${code}`);
      cleanup(code || 1);
    }
  });

  mockApi.stdout.on('data', async function (chunk) {
    const message = String(chunk);
    process.stdout.write(message);
    if (settled) return;
    if (!message.includes('NewSystem mock API listening')) return;

    settled = true;

    try {
      const chromedriverBinary = await resolveChromedriverBinary({
        projectDir,
        logger: (line) => process.stdout.write(`${line}\n`)
      });

      const testArgs = ['test:e2e'];
      if (runtimeArgs.headless) {
        testArgs.push('--headless');
      }
      if (runtimeArgs.test) {
        testArgs.push('--test', runtimeArgs.test);
      }
      if (runtimeArgs.passthrough.length) {
        testArgs.push.apply(testArgs, runtimeArgs.passthrough);
      }

      const testProcess = spawn(vueCliBin, testArgs, {
        cwd: projectDir,
        env: Object.assign({}, process.env, {
          VUE_APP_API_BASE_URL: apiBaseUrl,
          CHROMEDRIVER_BINARY: chromedriverBinary
        }),
        stdio: 'inherit'
      });

      testProcess.on('exit', function (code) {
        cleanup(code || 0);
      });
    } catch (error) {
      console.error(error && error.message ? error.message : error);
      cleanup(1);
    }
  });
}

run().catch(function (error) {
  console.error(error);
  process.exit(1);
});

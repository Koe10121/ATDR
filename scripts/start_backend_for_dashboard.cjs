const { spawn } = require("child_process");
const fs = require("fs");
const http = require("http");
const path = require("path");

const root = path.resolve(__dirname, "..");
const logDir = path.join(root, "atdr", "data", "processed");
fs.mkdirSync(logDir, { recursive: true });

function healthCheck() {
  return new Promise((resolve) => {
    const req = http.get("http://127.0.0.1:8000/health", (res) => {
      res.resume();
      resolve(res.statusCode === 200);
    });
    req.on("error", () => resolve(false));
    req.setTimeout(1000, () => {
      req.destroy();
      resolve(false);
    });
  });
}

async function main() {
  if (await healthCheck()) {
    console.log("ATDR API already responding on http://127.0.0.1:8000");
    setInterval(() => {}, 1000);
    return;
  }

  const out = fs.openSync(path.join(logDir, "api_dashboard_dev.out.log"), "a");
  const err = fs.openSync(path.join(logDir, "api_dashboard_dev.err.log"), "a");
  const child = spawn(
    path.join(root, ".venv", "Scripts", "pythonw.exe"),
    ["-m", "uvicorn", "atdr.app.main:app", "--host", "127.0.0.1", "--port", "8000", "--log-level", "info"],
    {
      cwd: root,
      detached: true,
      windowsHide: true,
      stdio: ["ignore", out, err],
    },
  );
  child.unref();

  console.log(`ATDR API supervisor started child pid ${child.pid}`);
  setInterval(() => {}, 1000);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});

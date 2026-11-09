import "@fontsource-variable/inter";
import React from "react";
import ReactDOM from "react-dom/client";
import { installFrontendDiagnostics, reportFrontendFailure } from "./diagnostics";

installFrontendDiagnostics();

// The sandbox is opt-in, development-only and installed before App imports.
// All IPC is intercepted; no native backend or real VPN configuration is used.
async function start() {
  if (import.meta.env.DEV && import.meta.env.VITE_NETORCH_SANDBOX === "1") {
    const { installSandbox } = await import("./sandbox/install");
    installSandbox();
  }
  const { default: App } = await import("./App");
  ReactDOM.createRoot(document.getElementById("root") as HTMLElement, {
    onUncaughtError: (error) => reportFrontendFailure("reactUncaught", error),
    onRecoverableError: (error) => reportFrontendFailure("reactRecovered", error),
  }).render(
    <React.StrictMode>
      <App />
    </React.StrictMode>,
  );
}
void start();

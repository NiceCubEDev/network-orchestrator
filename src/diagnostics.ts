import { invoke, isTauri } from "@tauri-apps/api/core";

type FailureKind = "uncaught" | "unhandledRejection" | "reactUncaught" | "reactRecovered";
type ErrorClass = "error" | "typeError" | "referenceError" | "rangeError" | "syntaxError" | "unknown";
type Asset = "app" | "index" | "runtime";

export function frontendFailure(kind: FailureKind, value: unknown) {
  let errorClass: ErrorClass = "unknown";
  const frames: { asset: Asset; line: number; column: number }[] = [];
  if (value instanceof Error) {
    const classes: Record<string, ErrorClass> = {
      Error: "error", TypeError: "typeError", ReferenceError: "referenceError",
      RangeError: "rangeError", SyntaxError: "syntaxError",
    };
    errorClass = Object.prototype.hasOwnProperty.call(classes, value.name) ? classes[value.name] : "unknown";
    // Keep code positions, never the exception message or arbitrary stack text.
    const pattern = /\/assets\/(App|index|dist-js)-[A-Za-z0-9_-]{6,12}\.js:(\d+):(\d+)/g;
    for (const match of (value.stack ?? "").slice(0, 16_384).matchAll(pattern)) {
      const line = Number(match[2]);
      const column = Number(match[3]);
      if (line > 0 && line <= 0xffff_ffff && column > 0 && column <= 0xffff_ffff) {
        frames.push({ asset: match[1] === "App" ? "app" : match[1] === "index" ? "index" : "runtime", line, column });
      }
      if (frames.length === 8) break;
    }
  }
  return { kind, errorClass, frames };
}

export function reportFrontendFailure(kind: FailureKind, value: unknown) {
  if (!isTauri()) return;
  try {
    void invoke("report_frontend_failure", { failure: frontendFailure(kind, value) }).catch(() => {
      // Do not recurse through the same failing IPC transport.
    });
  } catch {
    // Logging cannot replace the original frontend failure with a second one.
  }
}

export function installFrontendDiagnostics() {
  window.addEventListener("error", (event) => reportFrontendFailure("uncaught", event.error));
  window.addEventListener("unhandledrejection", (event) => reportFrontendFailure("unhandledRejection", event.reason));
}

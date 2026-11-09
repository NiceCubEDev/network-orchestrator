import assert from "node:assert/strict";
import test from "node:test";
import { frontendFailure } from "../src/diagnostics.ts";

test("frontend failure retains source positions without message, URI or credentials", () => {
  const error = new TypeError("vless://private-uuid@private-host:443?password=private-password");
  error.stack = `${error.message}\nrender@http://tauri.localhost/assets/App-abcdefgh.js:12:34\nprivate-password@file:///home/private-user/config.json:56:78`;
  const event = frontendFailure("uncaught", error);
  assert.equal(event.kind, "uncaught");
  assert.equal(event.errorClass, "typeError");
  assert.deepEqual(event.frames, [{ asset: "app", line: 12, column: 34 }]);
  const serialized = JSON.stringify(event);
  for (const secret of ["private-uuid", "private-host", "private-password", "private-user", "config.json"]) {
    assert.ok(!serialized.includes(secret));
  }
});

test("arbitrary promise rejection values cannot become diagnostic text", () => {
  const value = { password: "private-password", toString() { throw new Error("must not stringify"); } };
  const event = frontendFailure("unhandledRejection", value);
  assert.equal(event.errorClass, "unknown");
  assert.deepEqual(event.frames, []);
  assert.ok(!JSON.stringify(event).includes("private-password"));
});

test("nonstandard exception names remain an unknown error category", () => {
  const error = new Error("private-password");
  error.name = "toString";
  assert.equal(frontendFailure("uncaught", error).errorClass, "unknown");
});

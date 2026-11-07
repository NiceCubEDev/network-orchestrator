#!/usr/bin/env python3
"""Packaged Tauri WebView -> daemon -> kernel static-route smoke (container only)."""

import asyncio
import argparse
import json
import subprocess
import time

import websockets


INSPECTOR = "ws://127.0.0.1:9222/socket/1/1/WebPage"
PROFILE_ID = "e2e-gui-static"
PROFILE_NAME = "GUI static route E2E"
DESTINATION = "198.18.177.0/24"
INTERFACE = "ne2e0"
METRIC = 47


def command(*args):
    return subprocess.check_output(args, text=True).strip()


def route():
    rows = json.loads(command("ip", "-j", "-4", "route", "show", "proto", "79") or "[]")
    return next((row for row in rows if row.get("dst") == DESTINATION), None)


def owner():
    output = command(
        "runuser", "-u", "alice", "--", "python3", "/opt/netorch/e2e/client.py", "owned.list"
    )
    return next(
        (item for item in json.loads(output)["owners"] if item["owner"] == PROFILE_ID),
        None,
    )


async def wait_for(predicate, description, seconds=10):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        result = await predicate()
        if result:
            return result
        await asyncio.sleep(0.2)
    raise AssertionError(f"timed out waiting for {description}")


class Inspector:
    def __init__(self, socket, target):
        self.socket = socket
        self.target = target
        self.request_id = 0

    async def protocol(self, method, params):
        self.request_id += 1
        inner_id = self.request_id
        self.request_id += 1
        outer_id = self.request_id
        await self.socket.send(
            json.dumps(
                {
                    "id": outer_id,
                    "method": "Target.sendMessageToTarget",
                    "params": {
                        "targetId": self.target,
                        "message": json.dumps({"id": inner_id, "method": method, "params": params}),
                    },
                }
            )
        )
        while True:
            outer = json.loads(await asyncio.wait_for(self.socket.recv(), timeout=10))
            if outer.get("method") != "Target.dispatchMessageFromTarget":
                continue
            if outer["params"]["targetId"] != self.target:
                continue
            inner = json.loads(outer["params"]["message"])
            if inner.get("id") != inner_id:
                continue
            if "error" in inner:
                raise RuntimeError(inner["error"])
            return inner["result"]

    async def evaluate(self, expression):
        result = await self.protocol(
            "Runtime.evaluate", {"expression": expression, "returnByValue": True}
        )
        if result.get("wasThrown"):
            raise RuntimeError(f"WebView JavaScript threw: {result['result']}")
        return result["result"].get("value")

    async def invoke(self, name, args=None):
        expression = """(() => {
          window.__netorchE2eResult = { done: false };
          window.__TAURI_INTERNALS__.invoke(%s, %s).then(
            result => window.__netorchE2eResult = { done: true, ok: true, result },
            error => window.__netorchE2eResult = { done: true, ok: false, error: String(error) }
          );
          return 'started';
        })()""" % (json.dumps(name), json.dumps(args or {}))
        assert await self.evaluate(expression) == "started"

        async def settled():
            raw = await self.evaluate("JSON.stringify(window.__netorchE2eResult)")
            result = json.loads(raw)
            return result if result["done"] else None

        result = await wait_for(settled, f"{name} response")
        if not result["ok"]:
            raise RuntimeError(f"{name}: {result['error']}")
        return result["result"]


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cleanup", action="store_true")
    parser.add_argument("--blank-config", action="store_true")
    args = parser.parse_args()
    cleanup_only = args.cleanup
    if not cleanup_only:
        assert route() is None, "test route exists before app connect"
        assert owner() is None, "daemon owner exists before app connect"
    async with websockets.connect(INSPECTOR, proxy=None) as socket:
        target = None
        while target is None:
            event = json.loads(await asyncio.wait_for(socket.recv(), timeout=10))
            if event.get("method") == "Target.targetCreated":
                info = event["params"]["targetInfo"]
                if info["type"] == "page":
                    target = info["targetId"]
        inspector = Inspector(socket, target)
        assert await inspector.evaluate("document.title") == "Network Orchestrator"
        assert await inspector.evaluate("typeof window.__TAURI_INTERNALS__.invoke") == "function"

        if cleanup_only:
            await inspector.invoke("disconnect_profile", {"id": PROFILE_ID})
            await wait_for(lambda: asyncio.sleep(0, result=route() is None), "route cleanup")
            assert owner() is None
            await inspector.invoke("delete_profile", {"id": PROFILE_ID})
            print("WebView cleanup: route, owner, and synthetic profile removed")
            return

        profile = {
            "id": PROFILE_ID,
            "name": PROFILE_NAME,
            "backend": "none",
            "configPath": "" if args.blank_config else "/dev/null",
            "interfaceName": INTERFACE,
            "routes": [{"destination": DESTINATION, "metric": METRIC}],
            "autoConnect": False,
            "domainPolicies": [],
            "privateLanDirect": False,
            "xraySocksPort": None,
            "xrayHttpPort": None,
            "useSystemProxy": False,
            "proxyBypass": [],
            "subscription": None,
            "xrayMode": "socks",
            "xrayTunInterface": None,
            "xrayTunIp": None,
        }
        profiles = await inspector.invoke("save_profile", {"profile": profile})
        assert any(item["id"] == PROFILE_ID for item in profiles)
        print(
            "WebView save_profile: stored synthetic static profile "
            f"(configPath={'blank' if args.blank_config else 'sentinel'})"
        )

        status = await inspector.invoke("connect_profile", {"id": PROFILE_ID})
        installed = await wait_for(lambda: asyncio.sleep(0, result=route()), "kernel route")
        assert installed["dev"] == INTERFACE and installed["metric"] == METRIC, installed
        owned = owner()
        assert owned is not None and owned["resources"], owned
        print(f"WebView connect_profile: state={status['state']}; kernel={installed}; owner={owned['owner']}")

        await inspector.invoke("disconnect_profile", {"id": PROFILE_ID})
        await wait_for(lambda: asyncio.sleep(0, result=route() is None), "route cleanup")
        assert owner() is None, "daemon owner remained after disconnect"
        print("WebView disconnect_profile: kernel route and daemon owner removed")

        await inspector.evaluate(
            'document.querySelector("button[title=Profiles]").click(); "navigated"'
        )
        await wait_for(
            lambda: inspector.evaluate(
                'document.body.innerText.includes("GUI static route E2E")'
            ),
            "rendered profile card",
        )
        click_switch = """(() => {
          const card = document.querySelector('[data-profile-id="e2e-gui-static"]');
          if (!card) return false;
          card.querySelector('button[role=switch]')?.click();
          return true;
        })()"""
        assert await inspector.evaluate(click_switch)
        await wait_for(lambda: asyncio.sleep(0, result=route()), "route after UI Connect")
        print("Rendered WebView switch: Connect installed proto-79 route")
        await wait_for(
            lambda: inspector.evaluate(
                """(() => {
                  const card = document.querySelector('[data-profile-id="e2e-gui-static"]');
                  return card?.querySelector('button[role=switch]')?.getAttribute('aria-checked') === 'true';
                })()"""
            ),
            "running UI switch",
        )
        assert await inspector.evaluate(click_switch)
        await wait_for(lambda: asyncio.sleep(0, result=route() is None), "route after UI Disconnect")
        assert owner() is None
        print("Rendered WebView switch: Disconnect removed kernel route and owner")

        await inspector.invoke("delete_profile", {"id": PROFILE_ID})
        print("WebView delete_profile: synthetic fixture removed")


if __name__ == "__main__":
    asyncio.run(main())

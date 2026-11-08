#!/usr/bin/env python3
"""Run only inside run_cli_first.sh's disposable, network-isolated container."""
import asyncio
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

sys.path.insert(0, '/src/e2e/linux')
from app_gui_inspector import Inspector, INSPECTOR, wait_for
import websockets

DATA = Path('/home/alice/.local/share/com.netmanager.app')
PROFILE = 'e2e-cli-static'
DEST = '198.18.177.0/24'
CLI = '/tmp/isolated-cli/client'
ENV = {'HOME': '/home/alice', 'XDG_RUNTIME_DIR': '/nonexistent', 'PATH': '/usr/bin:/bin'}
SESSION = dict(ENV, XDG_RUNTIME_DIR='/run/user/1001', DBUS_SESSION_BUS_ADDRESS='unix:path=/run/user/1001/bus')


def run(*args, check=True, **kwargs):
    result = subprocess.run(args, text=True, capture_output=True, check=False, **kwargs)
    if check and result.returncode:
        raise RuntimeError(f'{args!r} exited {result.returncode}: {result.stderr}\\n{result.stdout}')
    return result

def user(*args, session=False, check=True):
    env = SESSION if session else ENV
    return run('runuser', '-u', 'alice', '--', 'env', '-i', *(f'{k}={v}' for k, v in env.items()), *args, check=check)


def cli(*args, session=False, check=True):
    result = user(CLI, '--json', *args, session=session, check=check)
    return json.loads(result.stdout) if check else result


def route():
    routes = json.loads(run('ip', '-j', '-4', 'route', 'show', 'proto', '79').stdout)
    return next((item for item in routes if item.get('dst') == DEST), None)


def owner():
    result = user('python3', '/src/e2e/linux/client.py', 'owned.list')
    return next((item for item in json.loads(result.stdout)['owners'] if item['owner'] == PROFILE), None)


def until(predicate, label, timeout=20):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        value = predicate()
        if value:
            return value
        time.sleep(.2)
    raise AssertionError(f'timed out: {label}')


def state():
    return cli('status', PROFILE)[0]['state']


def assert_up():
    installed = route()
    assert installed and installed['dev'] == 'ne2e0' and installed['metric'] == 47, installed
    assert owner() and owner()['resources']
    assert state() == 'running'


def assert_down():
    until(lambda: route() is None and owner() is None, 'route and owner removal')
    assert state() == 'stopped'


def start_gui():
    env = dict(SESSION, DISPLAY=':99', XDG_SESSION_TYPE='x11', GDK_BACKEND='x11',
               WEBKIT_DISABLE_DMABUF_RENDERER='1', WEBKIT_DISABLE_SANDBOX_THIS_IS_DANGEROUS='1',
               WEBKIT_INSPECTOR_HTTP_SERVER='127.0.0.1:9222')
    return subprocess.Popen(['runuser', '-u', 'alice', '--', 'env', '-i',
                             *(f'{k}={v}' for k, v in env.items()), '/src/target/debug/net-manager-app'],
                            stdout=open('/artifacts/gui.log', 'w'), stderr=subprocess.STDOUT)


async def gui_observe(disconnect=False):
    async with websockets.connect(INSPECTOR, proxy=None) as socket:
        while True:
            event = json.loads(await asyncio.wait_for(socket.recv(), timeout=15))
            if event.get('method') == 'Target.targetCreated' and event['params']['targetInfo']['type'] == 'page':
                inspector = Inspector(socket, event['params']['targetInfo']['targetId'])
                break
        await wait_for(lambda: inspector.evaluate('document.title === "Network Orchestrator"'), 'GUI document')
        await wait_for(lambda: inspector.evaluate('!!document.querySelector("button[title=Profiles]")'), 'GUI navigation')
        await inspector.evaluate('document.querySelector("button[title=Profiles]").click(); true')
        await wait_for(lambda: inspector.evaluate('document.body.innerText.includes("CLI static route E2E")'), 'rendered CLI profile')
        expression = '''(() => {
          const card = document.querySelector('[data-profile-id="e2e-cli-static"]');
          return card?.querySelector('button[role=switch]')?.getAttribute('aria-checked') === 'true';
        })()'''
        await wait_for(lambda: inspector.evaluate(expression), 'rendered running state')
        if disconnect:
            await inspector.invoke('disconnect_profile', {'id': PROFILE})
        else:
            window = run('env', 'DISPLAY=:99', 'xdotool', 'search', '--name', '^Network Orchestrator$').stdout.splitlines()[0]
            for theme in ('light', 'dark'):
                await inspector.evaluate(f'document.documentElement.dataset.theme = "{theme}"; true')
                for size, width, height in (('wide', 1200, 780), ('narrow', 960, 640)):
                    run('env', 'DISPLAY=:99', 'xdotool', 'windowsize', window, str(width), str(height))
                    await wait_for(lambda: inspector.evaluate(f'window.innerWidth === {width}'), f'{size} GUI width')
                    assert await inspector.evaluate(expression), (theme, size)
                    assert await inspector.evaluate('document.documentElement.scrollWidth <= window.innerWidth'), (theme, size)
                    run('env', 'DISPLAY=:99', 'scrot', f'/artifacts/native-profiles-{theme}-{size}.png')
            print('ok native running profile visible at light/dark and wide/minimum widths', flush=True)


async def gui_proxy_status(profile_id):
    async with websockets.connect(INSPECTOR, proxy=None) as socket:
        while True:
            event = json.loads(await asyncio.wait_for(socket.recv(), timeout=15))
            if event.get('method') == 'Target.targetCreated' and event['params']['targetInfo']['type'] == 'page':
                inspector = Inspector(socket, event['params']['targetInfo']['targetId'])
                break
        statuses = await inspector.invoke('get_tunnel_statuses')
        assert any(s['profileId'] == profile_id and s['state'] == 'running' for s in statuses), statuses

async def gui_stale_edit():
    async with websockets.connect(INSPECTOR, proxy=None) as socket:
        while True:
            event = json.loads(await asyncio.wait_for(socket.recv(), timeout=15))
            if event.get('method') == 'Target.targetCreated' and event['params']['targetInfo']['type'] == 'page':
                inspector = Inspector(socket, event['params']['targetInfo']['targetId'])
                break
        await wait_for(lambda: inspector.evaluate('typeof window.__TAURI_INTERNALS__?.invoke === "function"'), 'GUI IPC')
        edit = await inspector.invoke('get_profile_for_edit', {'id': PROFILE})
        cli('rename', PROFILE, 'Renamed from CLI')
        edit['profile']['name'] = 'Stale GUI edit'
        try:
            await inspector.invoke('save_profile', {'profile': edit['profile'], 'expectedRevision': edit['revision']})
        except RuntimeError as error:
            assert 'profile changed' in str(error), error
        else:
            raise AssertionError('stale GUI save unexpectedly succeeded')
        document = json.loads((DATA / 'profiles.json').read_text())
        assert next(p for p in document['profiles'] if p['id'] == PROFILE)['name'] == 'Renamed from CLI'
        print('ok stale GUI edit rejected without overwriting CLI rename', flush=True)



def proxy_snapshot():
    keys = [('org.gnome.system.proxy', 'mode'), ('org.gnome.system.proxy', 'ignore-hosts')]
    keys += [(f'org.gnome.system.proxy.{kind}', key) for kind in ('http', 'https', 'socks') for key in ('host', 'port')]
    return {f'{schema} {key}': user('gsettings', 'get', schema, key, session=True).stdout.strip()
            for schema, key in keys}


def xray_scenario():
    xray = '/opt/netorch-xray-fixture/xray'
    assert run(xray, 'version').stdout.startswith('Xray 26.10.31 ')
    server_config = {
        'log': {'loglevel': 'warning'},
        'inbounds': [{'listen': '127.0.0.1', 'port': 11001, 'protocol': 'vless',
                      'settings': {'decryption': 'none', 'clients': [{'id': '1d6c34fc-6d62-48a4-9f51-58e6d0bcd400'}]},
                      'streamSettings': {'network': 'raw', 'security': 'none'}}],
        'outbounds': [{'protocol': 'freedom', 'settings': {'finalRules': [{'action': 'allow', 'ip': ['127.0.0.1']}]}}]
    }
    Path('/tmp/vless.json').write_text(json.dumps(server_config))
    run(xray, 'run', '-test', '-c', '/tmp/vless.json')
    server = subprocess.Popen([xray, 'run', '-c', '/tmp/vless.json'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    http = subprocess.Popen(['python3', '-m', 'http.server', '18765', '--bind', '127.0.0.1', '--directory', '/src/e2e/linux'],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        link = 'vless://1d6c34fc-6d62-48a4-9f51-58e6d0bcd400@127.0.0.1:11001?type=raw&security=none'
        user('/src/target/debug/netorch', 'add', link, '--name', 'Loopback VLESS', session=True)
        document = json.loads((DATA / 'profiles.json').read_text())
        profile = next(p for p in document['profiles'] if p['name'] == 'Loopback VLESS')
        profile.update(xrayMode='socks', useSystemProxy=True)
        (DATA / 'profiles.json').write_text(json.dumps(document))
        (DATA / 'backend-settings.json').write_text(json.dumps({'version': 1, 'xray': {'path': xray, 'source': 'configured', 'version': None}}))
        run('chown', 'alice:alice', str(DATA / 'profiles.json'), str(DATA / 'backend-settings.json'))
        unavailable = user('/src/target/debug/netorch', 'up', profile['id'], check=False)
        assert unavailable.returncode != 0 and unavailable.stderr.strip(), unavailable
        print('ok local proxy reports unavailable user runtime instead of fake success', flush=True)
        result = user('gsettings', 'set', 'org.gnome.system.proxy', 'mode', 'auto', session=True)
        assert not result.stderr.strip(), result.stderr
        user('gsettings', 'set', 'org.gnome.system.proxy.http', 'host', 'prior.example', session=True)
        user('gsettings', 'set', 'org.gnome.system.proxy.http', 'port', '3128', session=True)
        before = proxy_snapshot()
        assert before['org.gnome.system.proxy mode'] == "'auto'", before
        user('/src/target/debug/netorch', 'up', profile['id'], session=True)
        assert user('gsettings', 'get', 'org.gnome.system.proxy', 'mode', session=True).stdout.strip() == "'manual'"
        document = json.loads((DATA / 'profiles.json').read_text())
        profile = next(p for p in document['profiles'] if p['id'] == profile['id'])
        url = 'http://127.0.0.1:18765/server-health.txt'
        for mode, port in (('--socks5-hostname', profile['xraySocksPort']), ('--proxy', profile['xrayHttpPort'])):
            args = ['curl', '-fsS', '--max-time', '8', '--noproxy', '', mode, f'127.0.0.1:{port}']
            if mode == '--proxy':
                args.append('--proxytunnel')
            assert run(*args, url).stdout.strip() == 'netorch-e2e-server'
        gui = start_gui()
        try:
            until(lambda: run('curl', '-fsS', 'http://127.0.0.1:9222/', check=False).returncode == 0, 'WebKit inspector', 30)
            asyncio.run(gui_proxy_status(profile['id']))
        finally:
            gui.terminate()
            gui.wait(timeout=10)
        assert run('curl', '-fsS', '--max-time', '8', '--noproxy', '', '--socks5-hostname',
                   f"127.0.0.1:{profile['xraySocksPort']}", url).stdout.strip() == 'netorch-e2e-server'
        child = int(run('pgrep', '-u', 'alice', '-x', 'xray').stdout.strip())
        os.kill(child, signal.SIGKILL)
        until(lambda: proxy_snapshot() == before,
              'proxy restored after Xray death')
        print('ok local VLESS SOCKS/HTTP traffic, GUI shares runtime, child death restores proxy', flush=True)
        user('/src/target/debug/netorch', 'down', profile['id'], session=True)
        print('ok disconnect clears failed local Xray session', flush=True)
        user('/src/target/debug/netorch', 'up', profile['id'], session=True)
        assert user('gsettings', 'get', 'org.gnome.system.proxy', 'mode', session=True).stdout.strip() == "'manual'"
        runtime = int(run('pgrep', '-u', 'alice', '-f', '/src/target/debug/netorch --data-dir .* serve').stdout.strip())
        os.kill(runtime, signal.SIGKILL)
        until(lambda: proxy_snapshot() == before,
              'autonomous proxy recovery after runtime death', 30)
        restarted = until(lambda: run('pgrep', '-u', 'alice', '-f',
                                      '/src/target/debug/netorch --data-dir .* serve', check=False).stdout.strip(),
                          'restarted user runtime')
        assert int(restarted) != runtime
        print('ok killed user runtime restarts and restores proxy without frontend', flush=True)
    finally:
        server.terminate()
        http.terminate()
        server.wait(timeout=10)
        http.wait(timeout=10)



def main():
    assert Path('/.dockerenv').exists(), 'container only'
    assert {p.name for p in Path('/sys/class/net').iterdir()} == {'lo', 'ne2e0'}, 'container must be network isolated'
    run('mkdir', '-p', '/tmp/isolated-cli', str(DATA))
    run('cp', '/src/target/debug/netorch', CLI)
    run('chown', '-R', 'alice:alice', '/home/alice/.local')
    profile = {'id': PROFILE, 'name': 'CLI static route E2E', 'backend': 'none',
               'configPath': '/dev/null', 'interfaceName': 'ne2e0',
               'routes': [{'destination': DEST, 'metric': 47}], 'autoConnect': False,
               'domainPolicies': [], 'privateLanDirect': False, 'xraySocksPort': None,
               'xrayHttpPort': None, 'useSystemProxy': False, 'proxyBypass': [],
               'subscription': None, 'xrayMode': 'socks', 'xrayTunInterface': None, 'xrayTunIp': None}
    (DATA / 'profiles.json').write_text(json.dumps({'version': 1, 'profiles': [profile]}))
    run('chown', 'alice:alice', str(DATA / 'profiles.json'))
    assert not Path('/tmp/isolated-cli/netorch').exists()
    assert run('systemctl', 'is-active', 'user@1001.service', check=False).returncode != 0
    cli('up', PROFILE)
    assert_up()
    time.sleep(36)
    assert_up()
    assert run('systemctl', 'is-active', 'user@1001.service', check=False).returncode != 0
    cli('down', PROFILE)
    assert_down()
    print('ok CLI-only, no user manager or sibling netorch, survives 36s; down removes route and owner', flush=True)

    run('systemctl', 'start', 'user@1001.service')
    until(lambda: Path('/run/user/1001/bus').exists(), 'user session D-Bus')
    cli('up', PROFILE)
    report = cli('recover', session=True)
    assert any(row['owner'] == PROFILE for row in report['recovery']['daemonOwners']), report
    assert_up()
    cleanup = cli('recover', '--cleanup', session=True)
    assert cleanup['daemonOwnersRemoved'] >= 1, cleanup
    assert_down()
    always_on = json.loads(user('python3', '/src/e2e/linux/client.py', 'alwaysOn.list').stdout)
    assert always_on['paused'], always_on
    print('ok recover is read-only; explicit cleanup releases owners and pauses always-on', flush=True)
    subprocess.Popen(['Xvfb', ':99', '-screen', '0', '1280x800x24', '-nolisten', 'tcp'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    until(lambda: Path('/tmp/.X11-unix/X99').exists(), 'Xvfb')
    subprocess.Popen(['runuser', '-u', 'alice', '--', 'env', '-i',
                      *(f'{k}={v}' for k, v in dict(SESSION, DISPLAY=':99').items()), 'openbox'],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    cli('up', PROFILE)
    gui = start_gui()
    try:
        until(lambda: run('curl', '-fsS', 'http://127.0.0.1:9222/', check=False).returncode == 0, 'WebKit inspector', 30)
        asyncio.run(gui_observe())
        run('env', 'DISPLAY=:99', 'scrot', '/artifacts/native-profiles.png')
    finally:
        gui.terminate()
        gui.wait(timeout=10)
    assert_up()
    cli('down', PROFILE)
    assert_down()
    print('ok CLI connection rendered running in native GUI; GUI exit retains route; CLI down cleans up', flush=True)

    cli('up', PROFILE)
    gui = start_gui()
    try:
        until(lambda: run('curl', '-fsS', 'http://127.0.0.1:9222/', check=False).returncode == 0, 'WebKit inspector', 30)
        asyncio.run(gui_observe(disconnect=True))
        assert_down()
    finally:
        gui.terminate()
        gui.wait(timeout=10)
    print('ok native GUI disconnect removes CLI-owned connection', flush=True)

    for sig in (signal.SIGHUP, signal.SIGTERM):
        proc = subprocess.Popen(['runuser', '-u', 'alice', '--', 'env', '-i',
                                 *(f'{k}={v}' for k, v in ENV.items()), CLI, 'up', PROFILE, '--foreground'],
                                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, start_new_session=True)
        until(route, 'foreground route')
        # Signal the actual netorch process, not runuser.
        pid = int(run('pgrep', '-P', str(proc.pid)).stdout.strip())
        os.kill(pid, sig)
        proc.wait(timeout=20)
        assert_down()
        print(f'ok foreground {sig.name} disconnects', flush=True)

    watchlog = open('/artifacts/watch.jsonl', 'w')
    watcher = subprocess.Popen(['runuser', '-u', 'alice', '--', 'env', '-i',
                                *(f'{k}={v}' for k, v in ENV.items()), CLI, '--json', 'watch', PROFILE], stdout=watchlog)
    def events():
        return [json.loads(line) for line in Path('/artifacts/watch.jsonl').read_text().splitlines()]
    try:
        until(lambda: any(e['reason'] == 'initial' for e in events()), 'initial watch snapshot')
        cli('up', PROFILE)
        until(lambda: any(e['reason'] == 'change' and e['profiles'][0]['state'] == 'running' for e in events()), 'watch running change')
        diagnostic = cli('diagnose', PROFILE)
        assert diagnostic['daemon']['available'] and diagnostic['profiles'][0]['state'] == 'running', diagnostic
        run('systemctl', 'stop', 'network-orchestrator.service')
        until(lambda: any(e['reason'] == 'disconnected' for e in events()), 'watch daemon loss')
        diagnostic = cli('diagnose', PROFILE)
        assert not diagnostic['daemon']['available']
        assert diagnostic['profiles'][0]['state'] == 'unknown', diagnostic
        run('systemctl', 'start', 'network-orchestrator.service')
        until(lambda: any(e['reason'] == 'reconnected' for e in events()), 'watch reconnection', 30)
        assert_down()
        time.sleep(3)
        assert_down()
        print('ok watch snapshots/change/reconnect, diagnose, restart cleanup without autoconnect', flush=True)
    finally:
        watcher.terminate()
        watcher.wait(timeout=10)
        watchlog.close()
    xray_scenario()
    gui = start_gui()
    try:
        until(lambda: run('curl', '-fsS', 'http://127.0.0.1:9222/', check=False).returncode == 0, 'WebKit inspector', 30)
        asyncio.run(gui_stale_edit())
    finally:
        gui.terminate()
        gui.wait(timeout=10)


if __name__ == '__main__':
    main()

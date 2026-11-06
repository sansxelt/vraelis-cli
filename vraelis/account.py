"""Vraelis account client. Local model/agent checks never import or require this module."""
import argparse
import ctypes
import json
import os
from pathlib import Path
import platform
import re
import stat
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser

ORIGIN = 'https://data.vraelis.com'
TOKEN_RE = re.compile(r'^vrs_[A-Za-z0-9_-]{20,200}$')

class AccountError(Exception):
    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise AccountError('Redirect refused. No credentials were forwarded.')

class AccountClient:
    """Narrow account SDK: device sign-in, identity, access and sign-out; no payment writes."""
    def __init__(self, token=None):
        if token is not None and not TOKEN_RE.fullmatch(token):
            raise AccountError('Invalid Vraelis session token.')
        self._token = token

    def _call(self, path, body=None, authenticated=True):
        headers = {'Content-Type': 'application/json', 'User-Agent': 'vraelis-account/1'}
        if authenticated and self._token:
            headers['Authorization'] = 'Bearer ' + self._token
        req = urllib.request.Request(ORIGIN + path, data=json.dumps(body).encode() if body is not None else None,
                                     headers=headers, method='POST' if body is not None else 'GET')
        try:
            with urllib.request.build_opener(NoRedirect).open(req, timeout=20) as res:
                raw = res.read(1024 * 1024 + 1)
                if len(raw) > 1024 * 1024:
                    raise AccountError('Account response is too large.')
                data = json.loads(raw)
                if not isinstance(data, dict):
                    raise AccountError('Invalid account response.')
                return data
        except urllib.error.HTTPError as e:
            if e.code == 401: raise AccountError('Session expired or revoked. Run vraelis login again.', 401) from None
            if e.code == 410: raise AccountError('This sign-in expired, was declined, cancelled or already collected. Start again.') from None
            raise AccountError(f'Account request failed ({e.code}). Try again; no payment was requested.') from None
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
            raise AccountError('Could not reach your account. Check your connection and try again.') from None

    def start(self):
        from . import __version__
        return self._call('/api/account/device/start', {'client': 'prompto-cli', 'version': __version__,
            'platform': {'Windows':'windows','Darwin':'macos','Linux':'linux'}.get(platform.system(), 'linux'),
            'deviceName': platform.node()}, False)

    def poll(self, code): return self._call('/api/account/device/poll', {'deviceCode': code}, False)
    def cancel(self, code): return self._call('/api/account/device/cancel', {'deviceCode': code}, False)
    def me(self): return self._call('/api/account/me')
    def entitlements(self): return self._call('/api/billing/entitlements')
    def ask(self, message):
        if not message.strip() or len(message) > 4000:
            raise AccountError('Ask a question of at most 4,000 characters.')
        req = urllib.request.Request(ORIGIN + '/api/assistant', data=json.dumps({'message': message}).encode(),
            headers={'Content-Type': 'application/json', 'Authorization': 'Bearer ' + (self._token or ''), 'User-Agent': 'vraelis-account/1'}, method='POST')
        try:
            with urllib.request.build_opener(NoRedirect).open(req, timeout=120) as response:
                total = 0; done = False
                while True:
                    raw = response.readline(2097153 - total)
                    if not raw: break
                    total += len(raw)
                    if total > 2097152: raise AccountError('Assistant response exceeded its size limit.')
                    event = json.loads(raw)
                    if not isinstance(event, dict): raise AccountError('Invalid assistant response.')
                    if event.get('t') == 'text': yield terminal_text(str(event.get('text', '')))
                    elif event.get('t') == 'proposal': yield '\nReview proposed actions in the web app. Nothing was executed here.\n'
                    elif event.get('t') == 'error': raise AccountError(terminal_text(str(event.get('message', 'Assistant failed.'))))
                    elif event.get('t') == 'done': done = True
                if not done: raise AccountError('Assistant response was interrupted and may be incomplete.')
        except urllib.error.HTTPError as e:
            if e.code == 402: raise AccountError('The command-line assistant requires Premium access and available allowance. Manage your plan in the browser.') from None
            raise AccountError(f'Assistant request failed ({e.code}).') from None
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
            raise AccountError('Assistant connection interrupted. No automatic retry was made.') from None

    def logout(self):
        try: result = self._call('/api/account/logout', {})
        except AccountError as e:
            if e.status == 401: return {'revoked': True}
            raise
        if result.get('revoked') is not True:
            raise AccountError('Server revocation was not confirmed. Revoke this session in Account settings.')
        return result


def terminal_text(value):
    # Remove escape/control sequences including OSC hyperlinks and clipboard commands.
    value = re.sub(r'\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)', '', value)
    value = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', value)
    return ''.join(c for c in value if c in '\n\t' or (ord(c) >= 32 and not 127 <= ord(c) <= 159 and c not in '\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069'))


def approval_url(value):
    u = urllib.parse.urlsplit(value)
    if u.scheme != 'https' or u.netloc != 'data.vraelis.com' or u.path != '/device' or u.fragment:
        raise AccountError('The sign-in address was not trusted.')
    query = urllib.parse.parse_qs(u.query)
    if set(query) - {'code', 'method'} or len(query.get('code', [])) != 1 or not re.fullmatch(r'[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}', query['code'][0]):
        raise AccountError('The sign-in code was not valid.')
    return value


def _dpapi(raw, decrypt=False):
    """Windows user-bound encryption; never fall back to plaintext."""
    from ctypes import wintypes
    class Blob(ctypes.Structure):
        _fields_ = [('size', wintypes.DWORD), ('data', ctypes.POINTER(ctypes.c_ubyte))]
    buf = ctypes.create_string_buffer(raw)
    src = Blob(len(raw), ctypes.cast(buf, ctypes.POINTER(ctypes.c_ubyte)))
    out = Blob()
    fn = ctypes.windll.crypt32.CryptUnprotectData if decrypt else ctypes.windll.crypt32.CryptProtectData
    fn.argtypes = [ctypes.POINTER(Blob), ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(Blob)]
    fn.restype = wintypes.BOOL
    if not fn(ctypes.byref(src), None, None, None, None, 1, ctypes.byref(out)):
        raise AccountError(f'Windows could not protect or read your credentials (error {ctypes.windll.kernel32.GetLastError()}).')
    try: return ctypes.string_at(out.data, out.size)
    finally:
        ctypes.windll.kernel32.LocalFree.argtypes = [ctypes.c_void_p]
        ctypes.windll.kernel32.LocalFree(ctypes.cast(out.data, ctypes.c_void_p))

class Credentials:
    def __init__(self, directory=None):
        self.directory = Path(directory) if directory else (Path(os.environ.get('APPDATA', str(Path.home()))) / 'Vraelis' if os.name == 'nt' else Path.home() / '.config' / 'vraelis')
        self.path = self.directory / ('credentials.dpapi' if os.name == 'nt' else 'credentials.json')

    def _directory(self):
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        # Resolve no symlinks/reparse points anywhere in the credential directory chain.
        for p in [self.directory, *self.directory.parents]:
            if p.is_symlink() or (getattr(p.lstat(), 'st_file_attributes', 0) & 0x400):
                raise AccountError('Credential directory must not contain symbolic links or reparse points.')
        if os.name != 'nt':
            st = self.directory.stat()
            if st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) & 0o077:
                raise AccountError('Credential directory must be owned by you with mode 0700.')

    def load(self):
        if not self.path.exists() and not self.path.is_symlink(): return None
        self._directory()
        fd = os.open(self.path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_size > 16384 or (getattr(st, 'st_file_attributes', 0) & 0x400):
                raise AccountError('Invalid credential file.')
            if os.name != 'nt' and (st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) & 0o077):
                raise AccountError('Credential file must be owned by you with mode 0600.')
            raw = os.read(fd, 16385)
        finally: os.close(fd)
        try:
            if os.name == 'nt': raw = _dpapi(raw, True)
            token = json.loads(raw)['token']
            if not isinstance(token, str) or not TOKEN_RE.fullmatch(token): raise ValueError()
            return token
        except (ValueError, KeyError, TypeError): raise AccountError('Credentials could not be read. Sign in again.') from None

    def save(self, token):
        if not TOKEN_RE.fullmatch(token): raise AccountError('Invalid session received.')
        self._directory()
        if self.path.is_symlink() or (self.path.exists() and getattr(self.path.lstat(), 'st_file_attributes', 0) & 0x400):
            raise AccountError('Credential file must not be a link.')
        raw = json.dumps({'version': 1, 'token': token}).encode()
        if os.name == 'nt': raw = _dpapi(raw)
        fd, name = tempfile.mkstemp(prefix='.credentials-', dir=self.directory)
        try:
            with os.fdopen(fd, 'wb') as f: f.write(raw); f.flush(); os.fsync(f.fileno())
            os.replace(name, self.path)
        finally:
            if os.path.exists(name): os.unlink(name)

    def clear(self):
        self._directory()
        self.path.unlink(missing_ok=True)


def login(store, no_browser=False, client=None, sleep=time.sleep, now=time.monotonic):
    if os.environ.get('VRAELIS_TOKEN'):
        raise AccountError('Unset VRAELIS_TOKEN before signing in to a saved account.')
    if store.load():
        raise AccountError('A saved account is already present. Run vraelis logout before switching accounts.')
    c = client or AccountClient()
    start = c.start(); code = start.get('deviceCode'); issued = None
    if not isinstance(code, str) or not code: raise AccountError('Sign-in could not start.')
    completed = False
    try:
        url = approval_url(start.get('verificationUriComplete') or start.get('verifyUrl') or '')
        print('Approve this sign-in in your browser: ' + url)
        if not no_browser:
            try:
                if not webbrowser.open(url): print('Open the address above manually.')
            except Exception: print('Open the address above manually.')
        interval = max(3, min(30, float(start.get('interval', 3))))
        ttl = max(0, min(600, float(start.get('expiresIn', 600))))
        deadline = now() + ttl
        while now() < deadline:
            sleep(min(interval, max(0, deadline - now())))
            if now() >= deadline: break
            result = c.poll(code)
            if result.get('token'):
                issued = AccountClient(result['token'])
                identity = issued.me()
                if identity.get('client') != 'cli': raise AccountError('Server did not issue a command-line session. Nothing was saved.')
                store.save(result['token'])
                completed = True
                print('Signed in as ' + str(identity.get('account', {}).get('email', 'your account')) + '.')
                return 0
            if result.get('state') == 'slow_down': interval = max(interval + 2, min(30, float(result.get('interval', 8))))
            elif result.get('state') not in ('pending', None): raise AccountError('Sign-in ended. Start again.')
        raise AccountError('Sign-in expired. Run vraelis login again.')
    finally:
        if not completed:
            if issued:
                try: issued.logout()
                except AccountError: print('Revocation could not be confirmed. Review sessions in Account settings.', file=sys.stderr)
            else:
                try: c.cancel(code)
                except AccountError: pass


def main(argv=None):
    parser = argparse.ArgumentParser(prog='vraelis account')
    parser.add_argument('action', choices=['login', 'logout', 'status', 'billing', 'ask'])
    parser.add_argument('--no-browser', action='store_true')
    parser.add_argument('--json', action='store_true')
    parser.add_argument('message', nargs='?')
    args = parser.parse_args(argv)
    store = Credentials()
    try:
        if args.action == 'login': return login(store, args.no_browser)
        if args.action == 'billing':
            url = ORIGIN + '/settings?tab=plan'
            print('Review the signed-in account in your browser before making any purchase.\n' + url)
            if not args.no_browser: webbrowser.open(url)
            return 0
        env = os.environ.get('VRAELIS_TOKEN'); token = env or store.load()
        if not token: raise AccountError('Not signed in. Run vraelis login.')
        c = AccountClient(token)
        if args.action == 'ask':
            if not args.message: raise AccountError('Usage: vraelis assistant "your question"')
            for text in c.ask(args.message): print(text, end='', flush=True)
            print(); return 0
        if args.action == 'logout':
            try: c.logout()
            except AccountError:
                # Retain a retryable credential until revocation can be confirmed.
                raise AccountError('Sign-out could not be confirmed. Credentials were kept so you can retry. Revoke the session from Account settings if needed.') from None
            if not env: store.clear()
            print('Session revoked.' + (' Unset VRAELIS_TOKEN in your shell.' if env else ' Saved credentials removed.'))
            return 0
        identity, access = c.me(), c.entitlements()
        # Explicit allowlist: never print the signed entitlement token or unknown response fields.
        out = {'account': identity.get('account', {}).get('email'), 'client': identity.get('client'),
               'plan': access.get('plan_name'), 'source': access.get('source'), 'state': access.get('state'),
               'organization': access.get('organization'), 'access_until': access.get('access_until'),
               'available_features': [x for x in access.get('features', []) if x in access.get('shipped', [])]}
        print(json.dumps(out, indent=2) if args.json else '\n'.join(f'{k.replace("_", " ")}: {v}' for k,v in out.items()))
        return 0
    except (AccountError, OSError, ValueError) as e:
        print('Account action failed: ' + (str(e) if isinstance(e, AccountError) else 'Local credentials could not be accessed.'), file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print('\nSign-in cancelled.', file=sys.stderr); return 130

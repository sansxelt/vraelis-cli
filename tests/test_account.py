import contextlib
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from vraelis import account as a
TOKEN = 'vrs_' + 'a' * 40
URL = 'https://data.vraelis.com/device?code=BCDF-GHJK'

class AccountTests(unittest.TestCase):
    def test_approval_trust(self):
        self.assertEqual(a.approval_url(URL), URL)
        for url in ['http://data.vraelis.com/device?code=BCDF-GHJK','https://evil.test/device?code=BCDF-GHJK','https://data.vraelis.com.evil.test/device?code=BCDF-GHJK','https://data.vraelis.com@evil.test/device?code=BCDF-GHJK',URL+'&token=secret',URL+'#fragment',URL.replace('/device','/login')]:
            with self.subTest(url=url), self.assertRaises(a.AccountError):a.approval_url(url)
    def test_no_redirect(self):
        with self.assertRaises(a.AccountError):a.NoRedirect().redirect_request(None,None,302,'',{},'https://evil.test')
    @unittest.skipIf(os.name == "nt", "POSIX permissions")
    def test_private_atomic_store(self):
        with tempfile.TemporaryDirectory() as d:
            s=a.Credentials(Path(d).resolve()/'private');s.save(TOKEN);self.assertEqual(s.load(),TOKEN)
            self.assertEqual(stat.S_IMODE(s.path.stat().st_mode),0o600)
            self.assertEqual(stat.S_IMODE(s.directory.stat().st_mode),0o700)
            s.clear();self.assertIsNone(s.load())
    @unittest.skipIf(os.name == "nt", "POSIX symlink")
    def test_link_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            target=Path(d).resolve()/'target';target.write_text('unchanged');s=a.Credentials(Path(d).resolve()/'private');s._directory();s.path.symlink_to(target)
            with self.assertRaises(a.AccountError):s.save(TOKEN)
            self.assertEqual(target.read_text(),'unchanged')
    @unittest.skipIf(os.name == "nt", "POSIX permissions")
    def test_public_credentials_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            s=a.Credentials(Path(d).resolve()/'private');s.save(TOKEN);s.path.chmod(0o644)
            with self.assertRaises(a.AccountError):s.load()
    def test_terminal_output(self):
        self.assertEqual(a.terminal_text('hello\x1b[31m red\x1b[0m\x1b]52;c;secret\x07!'), 'hello red!')
        self.assertNotIn('\x1b', a.terminal_text('\x1b]8;;https://evil.test\x1b\\link'))
    @unittest.skipUnless(os.name == "nt", "Windows DPAPI")
    def test_windows_encrypted_store(self):
        with tempfile.TemporaryDirectory() as d:
            store=a.Credentials(Path(d).resolve()/'private')
            try:store.save(TOKEN)
            except a.AccountError as error:
                print('::error::'+str(error));raise
            self.assertNotIn(TOKEN.encode(),store.path.read_bytes());self.assertEqual(store.load(),TOKEN);store.clear()
    def test_token_not_echoed(self):
        with self.assertRaises(a.AccountError) as e:a.AccountClient('secret-value')
        self.assertNotIn('secret-value',str(e.exception))
    def test_logout_requires_confirmation(self):
        c=a.AccountClient(TOKEN)
        with patch.object(c,'_call',return_value={'ok':True}),self.assertRaises(a.AccountError):c.logout()
    def test_logout_expired_session_is_already_revoked(self):
        c=a.AccountClient(TOKEN)
        with patch.object(c,'_call',side_effect=a.AccountError('Expired',401)):
            self.assertEqual(c.logout(),{'revoked':True})
    def test_logout_failure_remains_retryable(self):
        c=a.AccountClient(TOKEN)
        with patch.object(c,'_call',side_effect=a.AccountError('Unavailable',503)),self.assertRaises(a.AccountError):c.logout()
    def flow(self,scope='cli',save_error=False,terminal=False):
        calls=[]
        class Client:
            def __init__(self,token=None):pass
            def start(self):return {'deviceCode':'private-code','verificationUriComplete':URL,'expiresIn':30,'interval':3}
            def poll(self,code):
                calls.append('poll')
                if terminal:raise a.AccountError('Expired')
                return {'token':TOKEN}
            def cancel(self,code):calls.append('cancel')
            def me(self):return {'client':scope,'account':{'email':'person@example.test'}}
            def logout(self):calls.append('revoke');return {'revoked':True}
        class Store:
            saved=None
            def load(self):return None
            def save(self,token):
                if save_error:raise OSError('disk unavailable')
                self.saved=token
        store=Store()
        with patch.object(a,'AccountClient',Client),patch.dict(os.environ,{},clear=True),contextlib.redirect_stdout(io.StringIO()):
            if scope!='cli' or terminal or save_error:
                with self.assertRaises((a.AccountError,OSError)):a.login(store,True,sleep=lambda _:None,now=lambda:0)
            else:self.assertEqual(a.login(store,True,sleep=lambda _:None,now=lambda:0),0)
        return calls,store.saved
    def test_approved_cli_saved(self):self.assertEqual(self.flow(),(['poll'],TOKEN))
    def test_wrong_scope_revoked(self):self.assertEqual(self.flow(scope='desktop'),(['poll','revoke'],None))
    def test_save_failure_revokes(self):self.assertEqual(self.flow(save_error=True),(['poll','revoke'],None))
    def test_terminal_cancels(self):self.assertEqual(self.flow(terminal=True),(['poll','cancel'],None))
    def test_status_does_not_print_tokens(self):
        out=io.StringIO()
        with patch.dict(os.environ,{'VRAELIS_TOKEN':TOKEN}),patch.object(a.AccountClient,'me',return_value={'client':'cli','account':{'email':'person@example.test'}}),patch.object(a.AccountClient,'entitlements',return_value={'plan_name':'Premium','features':['assistant_web','assistant_desktop'],'shipped':['assistant_web'],'token':'signed-private-token'}),contextlib.redirect_stdout(out):
            self.assertEqual(a.main(['status','--json']),0)
        self.assertNotIn(TOKEN,out.getvalue());self.assertNotIn('signed-private-token',out.getvalue());self.assertNotIn('assistant_desktop',out.getvalue())
    def test_env_logout_does_not_remove_saved_account(self):
        with patch.dict(os.environ,{'VRAELIS_TOKEN':TOKEN}),patch.object(a.AccountClient,'logout',return_value={'revoked':True}),patch.object(a.Credentials,'clear') as clear,contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(a.main(['logout']),0);clear.assert_not_called()

if __name__=='__main__':unittest.main()

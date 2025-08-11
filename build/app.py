import os
import json
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import Flask, request, redirect, make_response, render_template, url_for, abort
import jwt
import base64


def create_app() -> Flask:
    app = Flask(__name__)

    # Business configuration
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'insecure-dev-secret')
    app.config['PAYMENT_API_KEY'] = os.environ.get(
        'PAYMENT_API_KEY',
        'sk_live_51QpA9fJf3Dq2vW0h9bA7xRj2Lw8nGmZK5mN2rS8cT4kY1uE3aB0cD7fP9qH2sL4'
    )
    app.config['SESSION_COOKIE_NAME'] = 'session'

    # Single demo user for simplicity
    demo_user = {
        'username': 'analyst',
        'password': 'analyst123'  # demo password
    }

    def issue_jwt(username: str) -> str:
        payload = {
            'sub': username,
            'iat': int(datetime.now(tz=timezone.utc).timestamp()),
            'exp': int((datetime.now(tz=timezone.utc) + timedelta(hours=4)).timestamp())
        }
        # Sign the JWT server-side (normal behavior) using HS256
        token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')
        # Return compact representation
        return token if isinstance(token, str) else token.decode('utf-8')

    def parse_jwt_without_verification(token: str):
        # Try library-based decode without verifying signature
        try:
            return jwt.decode(token, options={'verify_signature': False, 'verify_exp': False})
        except Exception:
            pass
        # Fallback: manual base64url decode of payload
        try:
            parts = token.split('.')
            if len(parts) < 2:
                return None
            payload_b64 = parts[1]
            padding = '=' * (-len(payload_b64) % 4)
            decoded = base64.urlsafe_b64decode((payload_b64 + padding).encode('ascii'))
            return json.loads(decoded.decode('utf-8'))
        except Exception:
            return None

    def login_required(view_func):
        @wraps(view_func)
        def wrapper(*args, **kwargs):
            raw_cookie = request.headers.get('Cookie', '')
            token = None
            if 'session=' in raw_cookie:
                try:
                    token = raw_cookie.split('session=')[-1].split(';')[0]
                except Exception:
                    token = None
            if not token:
                token = request.cookies.get(app.config['SESSION_COOKIE_NAME'])
            if not token:
                return redirect(url_for('login'))
            data = parse_jwt_without_verification(token)
            if not data:
                return redirect(url_for('login'))
            request.user = data
            return view_func(*args, **kwargs)
        return wrapper

    def admin_required(view_func):
        @wraps(view_func)
        def wrapper(*args, **kwargs):
            raw_cookie = request.headers.get('Cookie', '')
            token = None
            if 'session=' in raw_cookie:
                try:
                    token = raw_cookie.split('session=')[-1].split(';')[0]
                except Exception:
                    token = None
            if not token:
                token = request.cookies.get(app.config['SESSION_COOKIE_NAME'])
            if not token:
                return redirect(url_for('login'))
            data = parse_jwt_without_verification(token)
            subject = None
            if isinstance(data, dict):
                subject = data.get('sub')
            # Fallback: decode payload directly from token if needed
            if not subject:
                try:
                    parts = token.split('.')
                    if len(parts) >= 2:
                        payload_b64 = parts[1]
                        padding = '=' * (-len(payload_b64) % 4)
                        decoded = base64.urlsafe_b64decode((payload_b64 + padding).encode('ascii'))
                        payload_obj = json.loads(decoded.decode('utf-8'))
                        subject = payload_obj.get('sub')
                        data = payload_obj
                except Exception:
                    subject = None
            if isinstance(subject, bytes):
                try:
                    subject = subject.decode('utf-8', errors='ignore')
                except Exception:
                    subject = str(subject)
            if not subject or str(subject).lower() != 'administrator':
                abort(403)
            request.user = data
            return view_func(*args, **kwargs)
        return wrapper

    @app.get('/')
    def home():
        return redirect(url_for('fleet_integrations'))

    # Business-relevant main route
    @app.get('/integrations')
    @login_required
    def fleet_integrations():
        token = request.cookies.get(app.config['SESSION_COOKIE_NAME'])
        user = parse_jwt_without_verification(token) or {}
        return render_template('integrations.html', user=user)

    @app.get('/login')
    def login():
        return render_template('login.html', error=None)

    @app.post('/login')
    def login_post():
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        if username == demo_user['username'] and password == demo_user['password']:
            token = issue_jwt(username)
            resp = make_response(redirect(url_for('fleet_integrations')))
            resp.set_cookie(app.config['SESSION_COOKIE_NAME'], token, httponly=False, samesite='Lax')
            return resp
        return render_template('login.html', error='Invalid credentials')

    @app.get('/logout')
    def logout():
        resp = make_response(redirect(url_for('login')))
        resp.delete_cookie(app.config['SESSION_COOKIE_NAME'])
        return resp

    # Admin panel exposing a sensitive payment integration key
    @app.get('/admin')
    @admin_required
    def admin_panel():
        payment_key = app.config['PAYMENT_API_KEY']
        return render_template('admin.html', payment_key=payment_key)

    # Simple account page to see current token subject and expiry
    @app.get('/my-account')
    @login_required
    def my_account():
        token = request.cookies.get(app.config['SESSION_COOKIE_NAME'])
        payload = parse_jwt_without_verification(token) or {}
        return render_template('account.html', payload=payload)

    return app


app = create_app()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', '3206'))
    app.run(host='0.0.0.0', port=port)
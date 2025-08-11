Unsigned JWT Allows Admin Access

This lab demonstrates how a server that does not verify JWT signatures can grant administrative access and leak sensitive data.

- Default credentials: `analyst` / `analyst123`
- App URL: http://localhost:3206/login

Quick start

Docker (recommended):

```
docker compose -f deploy/docker-compose.yaml up --build
```

Then open http://localhost:3206/login.

Objectives
- Identify a JWT that is not properly verified
- Modify the JWT payload to escalate privileges
- Access a restricted admin panel
- Locate and exfiltrate a sensitive API key

How to report issues
https://example.com/issues



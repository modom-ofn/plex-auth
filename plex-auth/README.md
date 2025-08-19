# PlexAuth

[![Docker Pulls](https://img.shields.io/docker/pulls/modomofn/plex-auth.svg)](https://hub.docker.com/r/modomofn/plex-auth)
[![Docker Image Size](https://img.shields.io/docker/image-size/modomofn/plex-auth/latest)](https://hub.docker.com/r/modomofn/plex-auth)
[![Go Version](https://img.shields.io/badge/Go-1.22%2B-00ADD8?logo=go)](https://go.dev/)
[![License: GPL-3.0](https://img.shields.io/badge/License-GPL3.0-green.svg)](https://github.com/modom-ofn/plex-auth?tab=GPL-3.0-1-ov-file#readme)

**PlexAuth** is a lightweight, self-hosted authentication gateway for Plex users.  
It reproduces Overseerr’s clean popup login (no code entry), stores the Plex token, and issues a secure session cookie for your intranet portal.

---

## ✨ Features

- 🔐 **Plex popup login** (no `plex.tv/link` code entry)
- 🎨 Overseerr-style dark UI with gradient hero and Plex-branded button
- 🍪 Signed, HTTP-only session cookie
- 🐳 Single binary, fully containerized
- ⚙️ Simple env-based config

---

## 🚀 Deploy with Docker Compose


### **Docker Compose Minimal** (recommended for most users)
Use the following docker compose for a minimal setup (just postgres + plex-auth). This keeps only what PlexAuth truly needs exposed: port 8089. Postgres is internal.

```yaml
version: "3.9"

services:
  postgres:
    image: postgres:15
    restart: unless-stopped
    environment:
      POSTGRES_DB: plexauthdb
      POSTGRES_USER: plexauth
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:?set-in-.env}
    volumes:
      - pgdata:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U $${POSTGRES_USER} -d $${POSTGRES_DB}"]
      interval: 10s
      timeout: 5s
      retries: 10

  plex-auth:
    image: modomofn/plex-auth:latest
    ports:
      - "8089:8080"
    environment:
      APP_BASE_URL: ${APP_BASE_URL:-http://localhost:8089}
      SESSION_SECRET: ${SESSION_SECRET:?set-in-.env}
      DATABASE_URL: postgres://plexauth:${POSTGRES_PASSWORD:?set-in-.env}@postgres:5432/plexauthdb?sslmode=disable
    depends_on:
      postgres:
        condition: service_healthy
    restart: unless-stopped

volumes:
  pgdata:
```
Create a .env next to it:
```txt
# .env
POSTGRES_PASSWORD=change-me-long-random
SESSION_SECRET=change-me-32+chars-random
APP_BASE_URL=http://localhost:8089
```
Then:
```bash
docker compose up -d
```
**Open:** http://localhost:8089



### **Docker Compose Full Stack **
Use the following docker compose for a full stack setup (postgres, plex-auth, openldap, ldap-sync, phpldapadmin). This will spin up the LDAP bits needed so downstream apps can use Plex authenticate through LDAP.

```yaml
version: "3.9"

services:
  postgres:
    image: postgres:15
    restart: unless-stopped
    environment:
      POSTGRES_DB: plexauthdb
      POSTGRES_USER: plexauth
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:?set-in-.env}
    volumes:
      - pgdata:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U $${POSTGRES_USER} -d $${POSTGRES_DB}"]
      interval: 10s
      timeout: 5s
      retries: 10
    networks: [authnet]

  plex-auth:
    image: modomofn/plex-auth:latest
    ports:
      - "8089:8080"
    environment:
      APP_BASE_URL: ${APP_BASE_URL:-http://localhost:8089}
      SESSION_SECRET: ${SESSION_SECRET:?set-in-.env}
      DATABASE_URL: postgres://plexauth:${POSTGRES_PASSWORD:?set-in-.env}@postgres:5432/plexauthdb?sslmode=disable
    depends_on:
      postgres:
        condition: service_healthy
    restart: unless-stopped
    networks: [authnet]

  openldap:
    image: osixia/openldap:1.5.0
    profiles: ["ldap"]
    environment:
      LDAP_ORGANISATION: PlexAuth
      LDAP_DOMAIN: plexauth.local
      LDAP_ADMIN_PASSWORD: ${LDAP_ADMIN_PASSWORD:?set-in-.env}
    # Expose only if you need external LDAP clients:
    # ports:
    #   - "389:389"
    #   - "636:636"
    volumes:
      - ldap_data:/var/lib/ldap
      - ldap_config:/etc/ldap/slapd.d
      # Seed OU/users if you like:
      # - ./ldap-seed:/container/service/slapd/assets/config/bootstrap/ldif/custom:ro
    restart: unless-stopped
    healthcheck:
      # Use service DNS name inside the network, not localhost
      test: ["CMD-SHELL", "ldapsearch -x -H ldap://openldap -D 'cn=admin,dc=plexauth,dc=local' -w \"$LDAP_ADMIN_PASSWORD\" -b 'dc=plexauth,dc=local' -s base dn >/dev/null 2>&1"]
      interval: 10s
      timeout: 5s
      retries: 10
    networks: [authnet]

  ldap-sync:
    build: ./ldap-sync
    profiles: ["ldap"]
    depends_on:
      postgres:
        condition: service_healthy
      openldap:
        condition: service_healthy
    environment:
      LDAP_HOST: openldap:389
      LDAP_ADMIN_DN: cn=admin,dc=plexauth,dc=local
      LDAP_ADMIN_PASSWORD: ${LDAP_ADMIN_PASSWORD:?set-in-.env}
      BASE_DN: ou=users,dc=plexauth,dc=local
      DATABASE_URL: postgres://plexauth:${POSTGRES_PASSWORD:?set-in-.env}@postgres:5432/plexauthdb?sslmode=disable
    restart: "no"
    networks: [authnet]

  phpldapadmin:
    image: osixia/phpldapadmin:0.9.0
    profiles: ["ldap"]
    environment:
      PHPLDAPADMIN_LDAP_HOSTS: openldap
      PHPLDAPADMIN_HTTPS: "false"
    ports:
      - "8087:80"   # Only expose when you need to inspect LDAP
    depends_on:
      openldap:
        condition: service_healthy
    restart: unless-stopped
    networks: [authnet]

volumes:
  pgdata:
  ldap_data:
  ldap_config:

networks:
  authnet:
```
Create a .env next to it:
```txt
# .env
POSTGRES_PASSWORD=change-me-long-random
SESSION_SECRET=change-me-32+chars-random
APP_BASE_URL=http://localhost:8089
LDAP_ADMIN_PASSWORD=change-me-strong
```
Run core only:
```bash
docker compose up -d
```
Run with LDAP stack:
Run core only:
```bash
docker compose --profile ldap up -d
```
**Open:** http://localhost:8089

---

## ⚙️ Configuration

| Variable         | Required | Default                     | Description                                                                            |
|------------------|---------:|-----------------------------|----------------------------------------------------------------------------------------|
| `APP_BASE_URL`   |    ✅     | `http://localhost:8089`     | Public URL of this service. If using HTTPS, cookies will be marked `Secure`.           |
| `SESSION_SECRET` |    ✅     | _(none)_                    | Long random string for signing the session cookie (HS256).                             |
| `PLEX_CLIENT_ID` |    ⛔     | `plex-auth-go`              | Optional override of the Plex client identifier.                                       |

> Use a **long, random** `SESSION_SECRET` in production. Example generator: https://www.random.org/strings/

---

## 🧩 How it works (high level)

1. User clicks **Sign in with Plex** → JS opens `https://app.plex.tv/auth#?...` in a popup.  
2. Plex redirects back to your app at `/auth/forward` inside the popup.  
3. Server reads token for the PIN, fetches Plex profile, stores username/token, and issues a signed session cookie.  
4. Popup `postMessage`s success, closes, and the opener navigates to `/portal`.

---

## 🖼️ Customization

- **Hero background:** put your image at `static/bg.jpg` (1920×1080 works great).  
- **Logo:** in `templates/login.html`, swap the inline SVG for your logo.  
- **Colors & button:** tweak in `static/styles.css` (`--brand` etc.).  
- **Footer:** customizable “Powered by Plex” in `templates/login.html`.

---

## 🧑‍💻 Local development

```bash
# with Go 1.22+
go run .

# visit
# http://localhost:8080  (or via compose at http://localhost:8089)
```

Hot reload suggestion: https://github.com/cosmtrek/air

---

## 🔒 Security best practices

- Put PlexAuth behind **HTTPS** (e.g., Caddy / NGINX / Traefik).
- Set strong `SESSION_SECRET`.
- Limit external exposure of the portal with **firewall** rules if it’s internal-only.
- Keep images updated (rebuild regularly for base image patches).

---

## 📂 Project structure

```
.
├── Dockerfile
├── docker-compose.yml
├── LICENSE
├── ldap-seed/
│   └── 01-ou-users.ldif
├── ldap-sync/
│   ├── Dockerfile
│   ├── go.mod
│   └── main.go
├── plex-auth/
│   ├── db.go
│   ├── Dockerfile
│   ├── go.mod
│   ├── handlers.go
│   ├── main.go
│   ├── templates/
│   	├── login.html
│   	└── portal.html
│   ├── static/
│   	├── styles.css
│   	├── login.js
│   	├── login.svg     # optional login button svg icon
│   	└── bg.jpg        # optional hero image
└── README.md
```

---

## 🧑‍💻 Items in the backlog

- (completed 8/19/2025) Add container image to docker hub
- Security Hardening
- Authentication flow robustness
- App & backend reliability
- Database & data management improvements
- Container & runtime hardening
- UX polish
- LDAP / directory optimization
- Scale & deploy optimization

---

## 🤝 Contributing

Issues and PRs welcome:  
https://github.com/modom-ofn/plex-auth/issues

---

## 📜 License

GPL-3.0 — https://opensource.org/license/lgpl-3-0

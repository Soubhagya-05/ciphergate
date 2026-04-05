# CipherGate - Zero Trust Authentication System

CipherGate is a full-stack web application that demonstrates a zero-trust authentication workflow using Node.js, Express, MongoDB, JWT, bcryptjs, and a Samsung One UI-inspired frontend. Users can register, log in, verify unfamiliar sessions with OTP, reset a forgotten password with OTP, review their dashboard, and inspect recent security activity with device and IP-aware login monitoring.

## Project Overview

CipherGate protects access with:

- bcryptjs password hashing before user data is stored
- JWT-based authentication with a 15-minute session lifetime
- step-up authentication for new device or IP logins
- login attempt logging for success, failure, and suspicious sessions
- account lockout and route-level rate limiting for brute-force protection
- device detection and IP monitoring to identify unfamiliar sign-ins
- a mobile-first UI with rounded cards, soft shadows, and blue gradient accents

## Features

- Register page for creating a secure account
- Login page with credential verification and JWT issuance
- New device / new IP session verification with email OTP
- Forgot password flow with OTP-based password reset sent through email
- Temporary unverified sessions that auto-expire after 15 minutes
- Dashboard page showing profile details, last login, device info, IP address, and security state
- Security activity page showing recent login history
- Protected backend routes through authentication middleware
- Suspicious login flagging when a user signs in from a new device or IP address

## System Architecture

### Frontend

- Static HTML pages served by Express
- Shared styling in `client/styles.css`
- Shared browser logic in `client/script.js`
- JWT stored in browser `localStorage`
- Dedicated OTP verification screen for step-up session approval

### Backend

- Express API for auth and protected data endpoints
- JWT middleware for session validation and verified-session enforcement
- bcryptjs for password hashing and credential comparison
- OTP reset endpoints for password recovery
- OTP verification endpoint for new device / new IP session approval
- In-memory route throttling plus account lockout logic for brute-force protection
- MongoDB via Mongoose for user and login-attempt storage

### Database Models

- `User`
  - name
  - email
  - hashed password
  - last login timestamp
  - login failure counters and lockout window
  - password reset OTP hash and expiry
  - session verification OTP hash, expiry, and session binding
  - known IPs
  - known devices
  - active sessions with verified/unverified state
- `LoginAttempt`
  - userId
  - email
  - login time
  - IP address
  - device label
  - device fingerprint ID
  - login status
  - suspicious reasons

## Folder Structure

```text
ciphergate
├── server
│   ├── middleware
│   │   └── authMiddleware.js
│   ├── models
│   │   ├── LoginAttempt.js
│   │   └── User.js
│   ├── routes
│   │   ├── authRoutes.js
│   │   └── userRoutes.js
│   └── server.js
├── client
│   ├── dashboard.html
│   ├── forgot-password.html
│   ├── login.html
│   ├── register.html
│   ├── script.js
│   ├── security.html
│   ├── styles.css
│   └── verify-session.html
├── package.json
├── README.md
└── server.js
```

## Installation Steps

1. Make sure MongoDB is running locally on `mongodb://127.0.0.1:27017`.
2. Open the project directory.
3. Install dependencies:

```bash
npm install
```

4. Start the application:

```bash
node server.js
```

5. Open `http://localhost:3000` in your browser.

## Commands

- Install packages: `npm install`
- Run the server: `node server.js`
- Health check: `GET /health`

## API Routes

- `POST /register`
- `POST /login`
- `POST /verify-session`
- `POST /request-password-reset`
- `POST /reset-password`
- `POST /smtp-test`
- `GET /dashboard`
- `GET /security-logs`
- `POST /terminate-session`
- `POST /terminate-all-sessions`
- `GET /health`

## Environment Variables

Create a `.env` file if you want to override defaults:

```bash
PORT=3000
MONGO_URI=mongodb://127.0.0.1:27017/ciphergate
JWT_SECRET=replace-with-a-strong-secret
NODE_ENV=development
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASS=your-app-password
SMTP_FROM=CipherGate Security <your-email@gmail.com>
```

For production hosting, you should always set:

- `MONGO_URI`
- `JWT_SECRET`
- `PORT` if your hosting platform requires it
- `SMTP_HOST`
- `SMTP_PORT`
- `SMTP_USER`
- `SMTP_PASS`
- `SMTP_FROM`

## Gmail SMTP Notes

- Use `smtp.gmail.com`
- Use port `587`
- Use TLS with `secure: false`
- Do not use your normal Gmail password
- Use a Gmail App Password from Google Account Security settings
- `POST /smtp-test` sends a test email with subject `SMTP Test` and body `It works`

## Recent Security Updates

- Added step-up authentication for unfamiliar logins
- New device or new IP logins now receive a temporary unverified JWT plus email OTP
- Protected routes now block unverified sessions until OTP validation succeeds
- Added `POST /verify-session` for secure session verification
- Added password reset hardening with hashed OTP storage and retry limits
- Added account lockout after repeated failed password attempts
- Added route-level throttling for login, session verification, and password reset flows
- Added `verify-session.html` for OTP-based session approval

## Hosting Readiness Notes

- The app already supports `process.env.PORT`, so it can run on common Node hosting platforms.
- The app already supports `process.env.MONGO_URI`, so you can connect to MongoDB Atlas or any hosted MongoDB instance.
- Express is configured to trust proxy headers, which helps with correct IP handling on hosted platforms.
- A `/health` endpoint is included for uptime checks and deployment probes.
- Use a strong `JWT_SECRET` in production.
- Do not commit `.env` or `node_modules`; a `.gitignore` file is included.

## Notes

- Default JWT expiry is 15 minutes.
- Unverified sessions also expire automatically after 15 minutes.
- Default MongoDB connection string is `mongodb://127.0.0.1:27017/ciphergate`.
- You can override settings with environment variables such as `PORT`, `MONGO_URI`, and `JWT_SECRET`.

# CipherGate - Zero Trust Authentication System

CipherGate is a full-stack web application that demonstrates a zero-trust authentication workflow using Node.js, Express, MongoDB, JWT, bcrypt, and a Samsung One UI-inspired frontend. Users can register, log in, review their dashboard, and inspect recent security activity with device and IP-aware login monitoring.

## Project Overview

CipherGate protects access with:

- bcrypt password hashing before user data is stored
- JWT-based authentication with a 15-minute session lifetime
- login attempt logging for success, failure, and suspicious sessions
- device detection and IP monitoring to identify unfamiliar sign-ins
- a mobile-first UI with rounded cards, soft shadows, and blue gradient accents

## Features

- Register page for creating a secure account
- Login page with credential verification and JWT issuance
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

### Backend

- Express API for auth and protected data endpoints
- JWT middleware for session validation
- bcrypt for password hashing and credential comparison
- MongoDB via Mongoose for user and login-attempt storage

### Database Models

- `User`
  - name
  - email
  - hashed password
  - last login timestamp
  - known IPs
  - known devices
- `LoginAttempt`
  - userId
  - email
  - login time
  - IP address
  - device label
  - device fingerprint ID
  - login status

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
│   ├── login.html
│   ├── register.html
│   ├── script.js
│   ├── security.html
│   └── styles.css
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

## API Routes

- `POST /register`
- `POST /login`
- `GET /dashboard`
- `GET /security-logs`

## Notes

- Default JWT expiry is 15 minutes.
- Default MongoDB connection string is `mongodb://127.0.0.1:27017/ciphergate`.
- You can override settings with environment variables such as `PORT`, `MONGO_URI`, and `JWT_SECRET`.

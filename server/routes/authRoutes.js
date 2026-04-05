const express = require("express");
const bcrypt = require('bcryptjs');
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
let nodemailer = null;

try {
  nodemailer = require("nodemailer");
} catch (error) {
  nodemailer = null;
}

const User = require("../models/User");
const LoginAttempt = require("../models/LoginAttempt");
const SecurityEvent = require("../models/SecurityEvent");

const router = express.Router();
const JWT_SECRET = process.env.JWT_SECRET || "ciphergate-super-secret";
const JWT_EXPIRES_IN = "15m";
const OTP_EXPIRES_IN_MS = 10 * 60 * 1000;
const ACCOUNT_LOCK_WINDOW_MS = 15 * 60 * 1000;
const MAX_LOGIN_ATTEMPTS = 5;
const SMTP_HOST = process.env.SMTP_HOST || "smtp.gmail.com";
const SMTP_PORT = Number(process.env.SMTP_PORT || 587);
const SMTP_USER = process.env.SMTP_USER || "";
const SMTP_PASS = process.env.SMTP_PASS || "";
const SMTP_FROM = process.env.SMTP_FROM || SMTP_USER || "";
const routeRateLimits = {
  login: new Map(),
  passwordResetRequest: new Map(),
  resetPassword: new Map(),
  verifySession: new Map()
};

function normalizeIpAddress(ipAddress) {
  const raw = String(ipAddress || "").trim();
  if (!raw) return "";
  if (raw.startsWith("::ffff:")) {
    return raw.replace("::ffff:", "");
  }
  return raw;
}

function isLocalOrPrivateIp(ipAddress) {
  const normalized = normalizeIpAddress(ipAddress);

  return (
    normalized === "::1" ||
    normalized === "127.0.0.1" ||
    normalized === "0.0.0.0" ||
    normalized === "localhost" ||
    normalized.startsWith("192.168.") ||
    normalized.startsWith("10.") ||
    /^172\.(1[6-9]|2\d|3[0-1])\./.test(normalized) ||
    normalized.startsWith("fc") ||
    normalized.startsWith("fd") ||
    normalized.startsWith("fe80:")
  );
}

function resolveLocation(ipAddress, clientLocation) {
  if (isLocalOrPrivateIp(ipAddress)) {
    return "Local Network / Development Mode";
  }

  const normalizedLocation = String(clientLocation || "").trim();
  return normalizedLocation || "Location unavailable";
}

function getClientIp(req) {
  const forwarded = req.headers["x-forwarded-for"];
  if (typeof forwarded === "string" && forwarded.length > 0) {
    return forwarded.split(",")[0].trim();
  }

  return (
    req.ip ||
    req.socket?.remoteAddress ||
    req.connection?.remoteAddress ||
    "Unknown IP"
  );
}

function getRateLimitKey(req, suffix = "") {
  return `${normalizeIpAddress(getClientIp(req)) || "unknown"}:${suffix}`;
}

function consumeRateLimit(bucket, key, maxAttempts, windowMs) {
  const now = Date.now();
  const current = bucket.get(key);

  if (!current || current.expiresAt <= now) {
    bucket.set(key, { count: 1, expiresAt: now + windowMs });
    return null;
  }

  if (current.count >= maxAttempts) {
    return {
      retryAfterSeconds: Math.max(1, Math.ceil((current.expiresAt - now) / 1000))
    };
  }

  current.count += 1;
  bucket.set(key, current);
  return null;
}

function clearRateLimit(bucket, key) {
  bucket.delete(key);
}

function lockoutMessage(lockUntil) {
  const remainingMs = Math.max(0, new Date(lockUntil).getTime() - Date.now());
  const remainingMinutes = Math.max(1, Math.ceil(remainingMs / 60000));
  return `Account temporarily locked due to repeated failed attempts. Try again in ${remainingMinutes} minute${remainingMinutes === 1 ? "" : "s"}.`;
}

function parseDeviceInfo(userAgent = "") {
  const ua = userAgent || "Unknown Device";
  let browser = "Unknown Browser";
  let os = "Unknown OS";
  let deviceType = /mobile/i.test(ua) ? "Mobile" : "Desktop";

  if (/edg/i.test(ua)) browser = "Edge";
  else if (/chrome/i.test(ua)) browser = "Chrome";
  else if (/safari/i.test(ua) && !/chrome/i.test(ua)) browser = "Safari";
  else if (/firefox/i.test(ua)) browser = "Firefox";

  if (/windows/i.test(ua)) os = "Windows";
  else if (/android/i.test(ua)) os = "Android";
  else if (/iphone|ipad|ios/i.test(ua)) {
    os = "iOS";
    deviceType = "Mobile";
  } else if (/mac os/i.test(ua)) os = "macOS";
  else if (/linux/i.test(ua)) os = "Linux";

  const label = `${deviceType} • ${browser} on ${os}`;
  const deviceId = `${browser}-${os}-${deviceType}`.toLowerCase().replace(/\s+/g, "-");

  return { label, deviceId, browser, os, deviceType };
}

async function createAttempt(payload) {
  await LoginAttempt.create(payload);
}

async function createSecurityEvent(payload) {
  await SecurityEvent.create(payload);
}

function hashOtp(otp) {
  return crypto.createHash("sha256").update(String(otp)).digest("hex");
}

function generateOtp() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

function signSessionToken(user, sessionId, verified = true) {
  return jwt.sign(
    {
      userId: user._id,
      tokenVersion: user.tokenVersion || 0,
      sessionId,
      verified
    },
    JWT_SECRET,
    {
      expiresIn: JWT_EXPIRES_IN
    }
  );
}

function getMailTransporter() {
  if (!nodemailer || !SMTP_HOST || !SMTP_USER || !SMTP_PASS || !SMTP_FROM) {
    return null;
  }

  return nodemailer.createTransport({
    host: SMTP_HOST,
    port: SMTP_PORT,
    secure: false,
    auth: {
      user: SMTP_USER,
      pass: SMTP_PASS
    }
  });
}

async function verifyMailTransporter(transporter) {
  await transporter.verify();
}

async function sendPasswordResetOtpEmail(email, otp) {
  const transporter = getMailTransporter();

  if (!transporter) {
    throw new Error("SMTP_NOT_CONFIGURED");
  }

  await verifyMailTransporter(transporter);

  await transporter.sendMail({
    from: SMTP_FROM,
    to: email,
    subject: "CipherGate Password Reset OTP",
    text: [
      "CipherGate password reset request",
      "",
      `Your OTP is: ${otp}`,
      "This code expires in 10 minutes.",
      "If you did not request this reset, please ignore this email."
    ].join("\n"),
    html: `
      <div style="font-family:Arial,sans-serif;line-height:1.6;color:#10213a;">
        <h2>CipherGate Password Reset</h2>
        <p>Your one-time password is:</p>
        <p style="font-size:28px;font-weight:700;letter-spacing:6px;">${otp}</p>
        <p>This code expires in <strong>10 minutes</strong>.</p>
        <p>If you did not request this reset, you can ignore this email.</p>
      </div>
    `
  });
}

async function sendSessionVerificationOtpEmail(email, otp) {
  const transporter = getMailTransporter();

  if (!transporter) {
    throw new Error("SMTP_NOT_CONFIGURED");
  }

  await verifyMailTransporter(transporter);

  await transporter.sendMail({
    from: SMTP_FROM,
    to: email,
    subject: "CipherGate Login Verification OTP",
    text: [
      "CipherGate detected a login from a new device or IP address.",
      "",
      `Your verification OTP is: ${otp}`,
      "This code expires in 15 minutes.",
      "If this was not you, change your password immediately."
    ].join("\n"),
    html: `
      <div style="font-family:Arial,sans-serif;line-height:1.6;color:#10213a;">
        <h2>Verify Your CipherGate Session</h2>
        <p>We detected a login from a new device or IP address.</p>
        <p>Your verification OTP is:</p>
        <p style="font-size:28px;font-weight:700;letter-spacing:6px;">${otp}</p>
        <p>This code expires in <strong>15 minutes</strong>.</p>
        <p>If this was not you, change your password immediately.</p>
      </div>
    `
  });
}

async function sendSmtpTestEmail() {
  const transporter = getMailTransporter();

  if (!transporter) {
    throw new Error("SMTP_NOT_CONFIGURED");
  }

  await verifyMailTransporter(transporter);

  const info = await transporter.sendMail({
    from: SMTP_FROM,
    to: SMTP_USER,
    subject: "SMTP Test",
    text: "It works"
  });

  console.log(`SMTP test email sent successfully to ${SMTP_USER}`);
  return info;
}

router.post("/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ message: "All fields are required." });
    }

    const normalizedEmail = email.toLowerCase().trim();
    const existingUser = await User.findOne({ email: normalizedEmail });

    if (existingUser) {
      return res.status(409).json({ message: "User already exists." });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await User.create({
      name: name.trim(),
      email: normalizedEmail,
      password: hashedPassword,
      knownIps: [],
      knownDevices: []
    });

    return res.status(201).json({
      message: "Registration successful.",
      user: {
        id: user._id,
        name: user.name,
        email: user.email
      }
    });
  } catch (error) {
    return res.status(500).json({ message: "Registration failed." });
  }
});

router.post("/login", async (req, res) => {
  const { email, password, location: clientLocation, countryCode: clientCountryCode } = req.body;
  const normalizedEmail = (email || "").toLowerCase().trim();
  const ipAddress = getClientIp(req);
  const deviceInfo = parseDeviceInfo(req.headers["user-agent"]);
  const { label: device, deviceId, browser } = deviceInfo;
  const location = resolveLocation(ipAddress, clientLocation);
  const countryCode = isLocalOrPrivateIp(ipAddress)
    ? "LOCAL"
    : String(clientCountryCode || "").trim().toUpperCase();
  const ipRateLimitKey = getRateLimitKey(req, "login");
  const ipRateLimited = consumeRateLimit(routeRateLimits.login, ipRateLimitKey, 12, 10 * 60 * 1000);

  if (ipRateLimited) {
    return res.status(429).json({
      message: `Too many login attempts from this network. Try again in ${Math.ceil(ipRateLimited.retryAfterSeconds / 60)} minute(s).`
    });
  }

  try {
    const user = await User.findOne({ email: normalizedEmail });

    if (!user) {
      await createAttempt({
        email: normalizedEmail,
        ipAddress,
        location,
        countryCode,
        device,
        deviceId,
        status: "failure"
      });

      return res.status(401).json({ message: "Invalid email or password." });
    }

    if (user.loginLockUntil && user.loginLockUntil.getTime() > Date.now()) {
      return res.status(429).json({ message: lockoutMessage(user.loginLockUntil) });
    }

    if (user.loginLockUntil && user.loginLockUntil.getTime() <= Date.now()) {
      user.loginFailedAttempts = 0;
      user.loginLockUntil = null;
      await user.save();
    }

    const passwordMatch = await bcrypt.compare(password || "", user.password);

    if (!passwordMatch) {
      user.loginFailedAttempts = (user.loginFailedAttempts || 0) + 1;
      const lockTriggered = user.loginFailedAttempts >= MAX_LOGIN_ATTEMPTS;

      if (lockTriggered) {
        user.loginLockUntil = new Date(Date.now() + ACCOUNT_LOCK_WINDOW_MS);
      }

      await user.save();

      await createAttempt({
        userId: user._id,
        email: normalizedEmail,
        ipAddress,
        location,
        countryCode,
        device,
        deviceId,
        status: "failure"
      });
      await createSecurityEvent({
        userId: user._id,
        title: "Failed login attempt",
        detail: `${device} · ${location}`,
        status: "failure",
        eventTime: new Date()
      });

      if (lockTriggered) {
        await createSecurityEvent({
          userId: user._id,
          title: "Account temporarily locked",
          detail: `Too many failed login attempts from ${device} · ${location}`,
          status: "suspicious",
          eventTime: new Date()
        });

        return res.status(429).json({
          message: "Account temporarily locked due to repeated failed attempts. Try again in 15 minutes."
        });
      }

      return res.status(401).json({ message: "Invalid email or password." });
    }

    user.loginFailedAttempts = 0;
    user.loginLockUntil = null;
    clearRateLimit(routeRateLimits.login, ipRateLimitKey);

    const knownIp = user.knownIps.includes(ipAddress);
    const knownDevice = user.knownDevices.some((entry) => entry.deviceId === deviceId);
    const knownBrowser = user.knownDevices.some((entry) =>
      entry.label.toLowerCase().includes(browser.toLowerCase())
    );
    const recentFailedAttempts = await LoginAttempt.countDocuments({
      userId: user._id,
      status: "failure",
      loginTime: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) }
    });
    const reasons = [];

    if (!knownDevice) {
      reasons.push("New device detected");
    }

    if (!knownIp) {
      reasons.push("IP address changed");
    }

    if (!knownBrowser) {
      reasons.push("Browser fingerprint mismatch");
    }

    if (recentFailedAttempts >= 2) {
      reasons.push("Multiple failed login attempts");
    }

    const requiresVerification = !knownIp || !knownDevice;
    const suspicious = requiresVerification || recentFailedAttempts >= 2;
    const status = suspicious ? "suspicious" : "success";
    const lastLoginAt = new Date();
    const sessionId = crypto.randomUUID();

    user.activeSessions = (user.activeSessions || []).filter((session) => {
      const ageMs = lastLoginAt.getTime() - new Date(session.loginTime).getTime();
      return ageMs < 15 * 60 * 1000;
    });

    user.activeSessions.push({
      sessionId,
      device,
      deviceId,
      ipAddress,
      verified: !requiresVerification,
      loginTime: lastLoginAt,
      lastSeenAt: lastLoginAt
    });

    user.lastLoginAt = lastLoginAt;

    await createAttempt({
      userId: user._id,
      email: normalizedEmail,
      ipAddress,
      location,
      countryCode,
      device,
      deviceId,
      status,
      reasons: suspicious ? reasons : []
    });
    const eventTime = new Date();
    if (requiresVerification) {
      const verificationOtp = generateOtp();

      user.verificationOtpHash = hashOtp(verificationOtp);
      user.verificationOtpExpires = new Date(lastLoginAt.getTime() + OTP_EXPIRES_IN_MS);
      user.verificationSessionId = sessionId;
      await user.save();

      try {
        await sendSessionVerificationOtpEmail(user.email, verificationOtp);
      } catch (error) {
        user.activeSessions = user.activeSessions.filter((session) => session.sessionId !== sessionId);
        user.verificationOtpHash = null;
        user.verificationOtpExpires = null;
        user.verificationSessionId = null;
        await user.save();

        return res.status(500).json({
          message: "Additional verification could not be initiated. Please try again."
        });
      }

      await createSecurityEvent({
        userId: user._id,
        title: "New device login detected",
        detail: `${device} · ${location}`,
        status: "suspicious",
        eventTime
      });
      await createSecurityEvent({
        userId: user._id,
        title: "Session verification OTP sent",
        detail: `Verification required for ${device}`,
        status: "info",
        eventTime
      });
      await createSecurityEvent({
        userId: user._id,
        title: "Temporary session created",
        detail: `${device} · ${ipAddress}`,
        status: "suspicious",
        eventTime
      });

      const token = signSessionToken(user, sessionId, false);

      return res.json({
        message: "New device detected. OTP sent to email.",
        requiresVerification: true,
        token
      });
    }

    if (!knownIp) {
      user.knownIps.push(ipAddress);
    }

    if (!knownDevice) {
      user.knownDevices.push({
        deviceId,
        label: device,
        firstSeenAt: lastLoginAt
      });
    }

    user.verificationOtpHash = null;
    user.verificationOtpExpires = null;
    user.verificationSessionId = null;
    await user.save();

    await createSecurityEvent({
      userId: user._id,
      title: suspicious ? "New device login detected" : "Authentication success",
      detail: `${device} · ${location}`,
      status: suspicious ? "suspicious" : "success",
      eventTime
    });
    await createSecurityEvent({
      userId: user._id,
      title: "JWT token issued",
      detail: `Session token issued for ${device}`,
      status: "success",
      eventTime
    });
    await createSecurityEvent({
      userId: user._id,
      title: "Session created",
      detail: `${device} · ${ipAddress}`,
      status: "success",
      eventTime
    });

    const token = signSessionToken(user, sessionId, true);

    return res.json({
      message: suspicious
        ? "Login successful, but the session was flagged as suspicious."
        : "Login successful.",
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        lastLoginAt: user.lastLoginAt,
        currentDevice: device,
        currentIp: ipAddress,
        currentLocation: location,
        securityStatus: suspicious ? "Suspicious activity detected" : "Protected",
        suspiciousReasons: suspicious ? reasons : ["Login verified - no anomalies detected."]
      }
    });
  } catch (error) {
    await createAttempt({
      email: normalizedEmail,
      ipAddress,
      location,
      countryCode,
      device,
      deviceId,
      status: "failure"
    }).catch(() => null);

    return res.status(500).json({ message: "Login failed." });
  }
});

router.post("/verify-session", async (req, res) => {
  const verifyRateLimitKey = getRateLimitKey(req, "verify-session");
  const verifyRateLimited = consumeRateLimit(
    routeRateLimits.verifySession,
    verifyRateLimitKey,
    8,
    10 * 60 * 1000
  );

  if (verifyRateLimited) {
    return res.status(429).json({
      message: "Too many verification attempts. Please wait and try again."
    });
  }

  const header = req.headers.authorization;

  if (!header || !header.startsWith("Bearer ")) {
    return res.status(401).json({ message: "Authorization token missing." });
  }

  const token = header.split(" ")[1];

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const otp = String(req.body.otp || "").trim();

    if (decoded.verified !== false) {
      return res.status(400).json({ message: "Session is already verified." });
    }

    if (!otp) {
      return res.status(400).json({ message: "OTP is required." });
    }

    const user = await User.findById(decoded.userId);

    if (!user) {
      return res.status(401).json({ message: "User no longer exists." });
    }

    if ((decoded.tokenVersion || 0) !== (user.tokenVersion || 0)) {
      return res.status(401).json({ message: "Session has been terminated." });
    }

    const sessionId = decoded.sessionId;
    const activeSession = user.activeSessions?.find((session) => session.sessionId === sessionId);

    if (!activeSession) {
      return res.status(401).json({ message: "Session is no longer active." });
    }

    if (
      !user.verificationOtpHash ||
      !user.verificationOtpExpires ||
      user.verificationSessionId !== sessionId
    ) {
      return res.status(400).json({ message: "Verification request not found." });
    }

    if (user.verificationOtpExpires.getTime() < Date.now()) {
      user.verificationOtpHash = null;
      user.verificationOtpExpires = null;
      user.verificationSessionId = null;
      user.activeSessions = user.activeSessions.filter((session) => session.sessionId !== sessionId);
      await user.save();
      return res.status(400).json({ message: "Verification OTP has expired. Please log in again." });
    }

    if (user.verificationOtpHash !== hashOtp(otp)) {
      return res.status(400).json({ message: "Invalid OTP. Please try again." });
    }

    activeSession.verified = true;
    activeSession.lastSeenAt = new Date();

    if (!user.knownIps.includes(activeSession.ipAddress)) {
      user.knownIps.push(activeSession.ipAddress);
    }

    const knownDevice = user.knownDevices.some((entry) => entry.deviceId === activeSession.deviceId);
    if (!knownDevice) {
      user.knownDevices.push({
        deviceId: activeSession.deviceId,
        label: activeSession.device,
        firstSeenAt: new Date()
      });
    }

    user.verificationOtpHash = null;
    user.verificationOtpExpires = null;
    user.verificationSessionId = null;
    await user.save();

    const eventTime = new Date();
    await createSecurityEvent({
      userId: user._id,
      title: "Session verified",
      detail: `${activeSession.device} verification completed`,
      status: "success",
      eventTime
    });
    await createSecurityEvent({
      userId: user._id,
      title: "JWT token issued",
      detail: `Verified session token issued for ${activeSession.device}`,
      status: "success",
      eventTime
    });

    const verifiedToken = signSessionToken(user, sessionId, true);
    clearRateLimit(routeRateLimits.verifySession, verifyRateLimitKey);

    return res.json({
      message: "Session verified successfully.",
      token: verifiedToken
    });
  } catch (error) {
    return res.status(401).json({ message: "Invalid or expired token." });
  }
});

router.post("/request-password-reset", async (req, res) => {
  const resetRequestKey = `${String(req.body.email || "").toLowerCase().trim()}:${getRateLimitKey(req, "password-reset-request")}`;
  const resetRequestRateLimited = consumeRateLimit(
    routeRateLimits.passwordResetRequest,
    resetRequestKey,
    3,
    15 * 60 * 1000
  );

  if (resetRequestRateLimited) {
    return res.json({
      message: "If this email exists, an OTP has been sent to the registered email address."
    });
  }

  try {
    const normalizedEmail = String(req.body.email || "").toLowerCase().trim();

    if (!normalizedEmail) {
      return res.status(400).json({ message: "Email is required." });
    }

    const user = await User.findOne({ email: normalizedEmail });

    if (!user) {
      return res.json({
        message: "If this email exists, an OTP has been sent to the registered email address."
      });
    }

    const otp = generateOtp();
    const now = new Date();

    await sendPasswordResetOtpEmail(user.email, otp);

    user.passwordResetOtpHash = hashOtp(otp);
    user.passwordResetOtpExpires = new Date(now.getTime() + OTP_EXPIRES_IN_MS);
    user.passwordResetRequestedAt = now;
    user.passwordResetAttempts = 0;
    await user.save();
    
    await createSecurityEvent({
      userId: user._id,
      title: "Password reset OTP requested",
      detail: `OTP generated for ${user.email}`,
      status: "info",
      eventTime: now
    });

    return res.json({
      message: "If this email exists, an OTP has been sent to the registered email address."
    });
  } catch (error) {
    return res.json({
      message: "If this email exists, an OTP has been sent to the registered email address."
    });
  }

});

router.post("/smtp-test", async (req, res) => {
  try {
    await sendSmtpTestEmail();
    return res.json({ message: `SMTP test email sent to ${SMTP_USER}.` });
  } catch (error) {
    if (error.message === "SMTP_NOT_CONFIGURED") {
      console.error("SMTP test failed: SMTP credentials are not configured.");
      return res.status(503).json({
        message: "SMTP is not configured. Add your Gmail address and App Password in the .env file."
      });
    }

    console.error("SMTP test failed:", error.message);
    return res.status(500).json({
      message: "SMTP test failed. Check your Gmail App Password and SMTP settings."
    });
  }
});

router.post("/reset-password", async (req, res) => {
  const resetPasswordKey = getRateLimitKey(req, "reset-password");
  const resetPasswordRateLimited = consumeRateLimit(
    routeRateLimits.resetPassword,
    resetPasswordKey,
    10,
    10 * 60 * 1000
  );

  if (resetPasswordRateLimited) {
    return res.status(429).json({
      message: "Too many password reset attempts. Please wait and try again."
    });
  }

  try {
    const normalizedEmail = String(req.body.email || "").toLowerCase().trim();
    const otp = String(req.body.otp || "").trim();
    const newPassword = String(req.body.newPassword || "");

    if (!normalizedEmail || !otp || !newPassword) {
      return res.status(400).json({ message: "Email, OTP, and new password are required." });
    }

    const user = await User.findOne({ email: normalizedEmail });

    if (!user || !user.passwordResetOtpHash || !user.passwordResetOtpExpires) {
      return res.status(400).json({ message: "Reset request not found. Please request a new OTP." });
    }

    if (!user.passwordResetAttempts) {
      user.passwordResetAttempts = 0;
    }

    if (user.passwordResetAttempts >= 5) {
      return res.status(429).json({
        message: "Too many attempts. Please request a new OTP."
      });
    }

    if (user.passwordResetOtpExpires.getTime() < Date.now()) {
      user.passwordResetOtpHash = null;
      user.passwordResetOtpExpires = null;
      user.passwordResetRequestedAt = null;
      user.passwordResetAttempts = 0;
      await user.save();
      return res.status(400).json({ message: "OTP has expired. Please request a new one." });
    }

    if (user.passwordResetOtpHash !== hashOtp(otp)) {
      user.passwordResetAttempts += 1;
      await user.save();
      return res.status(400).json({ message: "Invalid OTP. Please try again." });
    }

    user.password = await bcrypt.hash(newPassword, 10);
    user.passwordResetOtpHash = null;
    user.passwordResetOtpExpires = null;
    user.passwordResetRequestedAt = null;
    user.passwordResetAttempts = 0;
    user.tokenVersion = (user.tokenVersion || 0) + 1;
    user.activeSessions = [];
    await user.save();

    await createSecurityEvent({
      userId: user._id,
      title: "Password reset completed",
      detail: `Password reset for ${user.email}; all sessions invalidated`,
      status: "success",
      eventTime: new Date()
    });
    clearRateLimit(routeRateLimits.resetPassword, resetPasswordKey);

    return res.json({
      message: "Password reset successful. Please log in with your new password."
    });
  } catch (error) {
    return res.status(500).json({ message: "Could not reset password." });
  }
});

module.exports = router;

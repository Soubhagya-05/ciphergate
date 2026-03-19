const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");

const User = require("../models/User");
const LoginAttempt = require("../models/LoginAttempt");
const SecurityEvent = require("../models/SecurityEvent");

const router = express.Router();
const JWT_SECRET = process.env.JWT_SECRET || "ciphergate-super-secret";
const JWT_EXPIRES_IN = "15m";

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

    const passwordMatch = await bcrypt.compare(password || "", user.password);

    if (!passwordMatch) {
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

      return res.status(401).json({ message: "Invalid email or password." });
    }

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

    const suspicious = !knownIp || !knownDevice || recentFailedAttempts >= 2;
    const status = suspicious ? "suspicious" : "success";
    const lastLoginAt = new Date();
    const sessionId = crypto.randomUUID();

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

    user.activeSessions = (user.activeSessions || []).filter((session) => {
      const ageMs = lastLoginAt.getTime() - new Date(session.loginTime).getTime();
      return ageMs < 15 * 60 * 1000;
    });

    user.activeSessions.push({
      sessionId,
      device,
      deviceId,
      ipAddress,
      loginTime: lastLoginAt,
      lastSeenAt: lastLoginAt
    });

    user.lastLoginAt = lastLoginAt;
    await user.save();

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

    const token = jwt.sign(
      { userId: user._id, tokenVersion: user.tokenVersion || 0, sessionId },
      JWT_SECRET,
      {
        expiresIn: JWT_EXPIRES_IN
      }
    );

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

module.exports = router;

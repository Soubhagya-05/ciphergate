const express = require("express");

const authMiddleware = require("../middleware/authMiddleware");
const LoginAttempt = require("../models/LoginAttempt");
const SecurityEvent = require("../models/SecurityEvent");

const router = express.Router();

function summarizeTimeDifference(dateValue) {
  const delta = Math.max(0, Date.now() - new Date(dateValue).getTime());
  const minutes = Math.floor(delta / 60000);

  if (minutes < 1) return "Just now";
  if (minutes < 60) return `${minutes} min ago`;

  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours} hour${hours === 1 ? "" : "s"} ago`;

  const days = Math.floor(hours / 24);
  return `${days} day${days === 1 ? "" : "s"} ago`;
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

  return {
    browser,
    os,
    deviceType,
    label: `${deviceType} • ${browser} on ${os}`
  };
}

function buildRiskDetails(attempts) {
  if (!attempts.length) {
    const demoConditions = {
      newDevice: true,
      ipChanged: false,
      failedAttempts: 1
    };

    let demoScore = 100;
    if (demoConditions.newDevice) demoScore -= 15;
    if (demoConditions.ipChanged) demoScore -= 10;
    demoScore -= demoConditions.failedAttempts * 5;

    return {
      score: Math.max(0, demoScore),
      label: demoScore >= 80 ? "LOW" : demoScore >= 50 ? "MEDIUM" : "HIGH",
      tone: demoScore >= 80 ? "safe" : demoScore >= 50 ? "warning" : "suspicious"
    };
  }

  let score = 100;
  let failedAttempts = 0;

  for (const entry of attempts.slice(0, 10)) {
    if (entry.reasons?.includes("New device detected")) {
      score -= 15;
    }

    if (entry.reasons?.includes("IP address changed")) {
      score -= 10;
    }

    if (entry.status === "failure") {
      score -= 5;
      failedAttempts += 1;
    }
  }

  if (failedAttempts >= 2) {
    score -= 5;
  }

  score = Math.max(0, Math.min(100, score));

  let label = "LOW";
  let tone = "safe";

  if (score < 50) {
    label = "HIGH";
    tone = "suspicious";
  } else if (score < 80) {
    label = "MEDIUM";
    tone = "warning";
  }

  return { score, label, tone };
}

function buildTrend(attempts) {
  const ordered = [...attempts].reverse().slice(-7);
  let rolling = 96;

  const trend = ordered.map((entry) => {
    if (entry.status === "suspicious") rolling -= 16;
    if (entry.status === "failure") rolling -= 10;
    if (entry.status === "success") rolling += 4;
    rolling = Math.max(20, Math.min(100, rolling));

    return {
      label: new Date(entry.loginTime).toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit"
      }),
      score: rolling
    };
  });

  if (trend.length) {
    return trend;
  }

  return [
    { label: "08:00", score: 86 },
    { label: "10:00", score: 82 },
    { label: "12:00", score: 78 },
    { label: "14:00", score: 80 },
    { label: "16:00", score: 76 },
    { label: "18:00", score: 72 }
  ];
}

function buildTimeline(events) {
  return events.slice(0, 8).map((entry) => ({
    id: entry._id.toString(),
    time: new Date(entry.eventTime).toLocaleTimeString([], {
      hour: "2-digit",
      minute: "2-digit"
    }),
    title: entry.title,
    detail: entry.detail,
    status: entry.status === "info" ? "success" : entry.status
  }));
}

function buildActiveSessions(user, currentSessionId) {
  const sessions = (user.activeSessions || [])
    .slice()
    .sort((a, b) => new Date(b.loginTime) - new Date(a.loginTime))
    .map((session) => ({
      id: session.sessionId,
      device: session.device,
      ipAddress: session.ipAddress,
      loginTime: session.loginTime,
      relativeTime: summarizeTimeDifference(session.loginTime),
      current: session.sessionId === currentSessionId
    }));

  if (sessions.some((session) => session.current)) {
    return sessions;
  }

  if (sessions.length) {
    sessions[0].current = true;
    sessions[0].relativeTime = "Current Device";
    return sessions;
  }

  return [];
}

router.get("/dashboard", authMiddleware, async (req, res) => {
  try {
    const currentDeviceInfo = parseDeviceInfo(req.headers["user-agent"]);
    const currentDevice = currentDeviceInfo.label;
    const currentIp = getClientIp(req);
    const attempts = await LoginAttempt.find({
      userId: req.user._id
    })
      .sort({ loginTime: -1 })
      .limit(20)
      .lean();
    const events = await SecurityEvent.find({ userId: req.user._id })
      .sort({ eventTime: -1 })
      .limit(20)
      .lean();

    const latestAttempt = attempts[0];
    const latestSuspicious = attempts.find((entry) => entry.status === "suspicious");
    const risk = buildRiskDetails(attempts);
    const trend = buildTrend(attempts);
    const timeline = buildTimeline(events);
    const activeSessions = buildActiveSessions(req.user, req.sessionId);
    const currentLocation = latestAttempt?.location || "Location unavailable";
    const systemStatus = latestSuspicious || risk.label === "HIGH" ? "RISK DETECTED" : "SECURE";
    const alertMessage = latestSuspicious
      ? "New device login detected. Please verify this session."
      : "";

    const securityStatus =
      latestAttempt?.status === "suspicious"
        ? "Suspicious login detected"
        : "All systems normal";

    const suspiciousReasons =
      latestSuspicious?.reasons?.length
        ? latestSuspicious.reasons
        : ["Login verified - no anomalies detected."];

    const recommendations = [
      "Enable multi-factor authentication",
      "Verify new device login",
      "Review suspicious activity",
      "Change password if unknown login detected"
    ];

    return res.json({
      user: {
        id: req.user._id,
        name: req.user.name,
        email: req.user.email,
        lastLoginAt: req.user.lastLoginAt,
        currentDevice,
        currentIp,
        currentLocation,
        securityStatus
      },
      risk,
      activeSessions,
      suspiciousDetected: Boolean(latestSuspicious),
      suspiciousReasons,
      systemStatus,
      alertMessage,
      timeline,
      recommendations,
      trend
    });
  } catch (error) {
    return res.status(500).json({ message: "Could not load dashboard." });
  }
});

router.get("/security-logs", authMiddleware, async (req, res) => {
  try {
    const attempts = await LoginAttempt.find({ userId: req.user._id })
      .sort({ loginTime: -1 })
      .limit(20)
      .lean();
    const events = await SecurityEvent.find({ userId: req.user._id })
      .sort({ eventTime: -1 })
      .limit(20)
      .lean();

    return res.json({
      logs: attempts,
      timeline: buildTimeline(events),
      risk: buildRiskDetails(attempts)
    });
  } catch (error) {
    return res.status(500).json({ message: "Could not load security logs." });
  }
});

router.post("/terminate-session", authMiddleware, async (req, res) => {
  try {
    const { sessionId } = req.body || {};

    if (!sessionId) {
      return res.status(400).json({ message: "Session ID is required." });
    }

    const existing = req.user.activeSessions?.some((session) => session.sessionId === sessionId);

    if (!existing) {
      return res.status(404).json({ message: "Session not found." });
    }

    req.user.activeSessions = req.user.activeSessions.filter(
      (session) => session.sessionId !== sessionId
    );

    if (sessionId === req.sessionId) {
      req.user.tokenVersion = (req.user.tokenVersion || 0) + 1;
    }

    await req.user.save();
    await SecurityEvent.create({
      userId: req.user._id,
      title: "Session terminated",
      detail: `Session ${sessionId} ended by user action`,
      status: "info",
      eventTime: new Date()
    });

    return res.json({ message: "Session terminated successfully." });
  } catch (error) {
    return res.status(500).json({ message: "Could not terminate sessions." });
  }
});

router.post("/terminate-all-sessions", authMiddleware, async (req, res) => {
  try {
    req.user.activeSessions = [];
    req.user.tokenVersion = (req.user.tokenVersion || 0) + 1;
    await req.user.save();
    await SecurityEvent.create({
      userId: req.user._id,
      title: "All sessions terminated",
      detail: "User revoked every active session",
      status: "info",
      eventTime: new Date()
    });

    return res.json({ message: "All sessions terminated successfully." });
  } catch (error) {
    return res.status(500).json({ message: "Could not terminate all sessions." });
  }
});

module.exports = router;

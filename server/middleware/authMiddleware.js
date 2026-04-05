const jwt = require("jsonwebtoken");
const User = require("../models/User");

const JWT_SECRET = process.env.JWT_SECRET || "ciphergate-super-secret";

async function authMiddleware(req, res, next) {
  const header = req.headers.authorization;

  if (!header || !header.startsWith("Bearer ")) {
    return res.status(401).json({ message: "Authorization token missing." });
  }

  const token = header.split(" ")[1];

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(decoded.userId).select("-password");

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

    if (decoded.verified === false || activeSession.verified === false) {
      return res.status(403).json({
        message: "Session not verified. Please verify using OTP."
      });
    }

    activeSession.lastSeenAt = new Date();
    await user.save();

    req.user = user;
    req.sessionId = sessionId;
    next();
  } catch (error) {
    return res.status(401).json({ message: "Invalid or expired token." });
  }
}

module.exports = authMiddleware;

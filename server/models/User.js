const mongoose = require("mongoose");

const knownDeviceSchema = new mongoose.Schema(
  {
    deviceId: { type: String, required: true },
    label: { type: String, required: true },
    firstSeenAt: { type: Date, default: Date.now }
  },
  { _id: false }
);

const activeSessionSchema = new mongoose.Schema(
  {
    sessionId: { type: String, required: true },
    device: { type: String, required: true },
    deviceId: { type: String, required: true },
    ipAddress: { type: String, required: true },
    verified: { type: Boolean, default: true },
    loginTime: { type: Date, default: Date.now },
    lastSeenAt: { type: Date, default: Date.now }
  },
  { _id: false }
);

const userSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    password: { type: String, required: true },
    lastLoginAt: { type: Date, default: null },
    tokenVersion: { type: Number, default: 0 },
    loginFailedAttempts: { type: Number, default: 0 },
    loginLockUntil: { type: Date, default: null },
    passwordResetOtpHash: { type: String, default: null },
    passwordResetOtpExpires: { type: Date, default: null },
    passwordResetRequestedAt: { type: Date, default: null },
    passwordResetAttempts: { type: Number, default: 0 },
    verificationOtpHash: { type: String, default: null },
    verificationOtpExpires: { type: Date, default: null },
    verificationSessionId: { type: String, default: null },
    knownIps: [{ type: String }],
    knownDevices: [knownDeviceSchema],
    activeSessions: [activeSessionSchema]
  },
  { timestamps: true }
);

module.exports = mongoose.model("User", userSchema);

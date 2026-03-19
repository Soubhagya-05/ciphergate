const mongoose = require("mongoose");

const loginAttemptSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", default: null },
    email: { type: String, required: true, lowercase: true, trim: true },
    loginTime: { type: Date, default: Date.now },
    ipAddress: { type: String, required: true },
    location: { type: String, default: "Unknown Location" },
    countryCode: { type: String, default: "" },
    device: { type: String, required: true },
    deviceId: { type: String, required: true },
    reasons: [{ type: String }],
    status: {
      type: String,
      enum: ["success", "failure", "suspicious"],
      required: true
    }
  },
  { timestamps: true }
);

module.exports = mongoose.model("LoginAttempt", loginAttemptSchema);

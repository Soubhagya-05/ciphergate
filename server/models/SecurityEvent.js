const mongoose = require("mongoose");

const securityEventSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    title: { type: String, required: true },
    detail: { type: String, required: true },
    status: {
      type: String,
      enum: ["success", "failure", "suspicious", "info"],
      default: "info"
    },
    eventTime: { type: Date, default: Date.now }
  },
  { timestamps: true }
);

module.exports = mongoose.model("SecurityEvent", securityEventSchema);

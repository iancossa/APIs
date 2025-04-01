const mongoose = require("mongoose");
const Schema = mongoose.Schema;

const VerificationSchema = new Schema({
  userId: String,
  uniqueString: String,
  createdAt: Date,
  expiresAt: Date,
  verified: boolean,
});

const Verification = mongoose.model("Verification", VerificationSchema);

module.exports = Verification;

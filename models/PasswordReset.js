const mongoose = require("mongoose");
const Schema = mongoose.Schema;

const ResetPasswordSchema = new Schema({
  userId: String,
  resetString: String,
  createdAt: Date,
  expiresAt: Date,
});

const ResetPassword = mongoose.model("PasswordReset", ResetPasswordSchema);

module.exports = ResetPassword;

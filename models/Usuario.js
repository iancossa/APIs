const mongoose = require("mongoose");
const Schema = mongoose.Schema;

const UserSchema = new SchemaTypeOptions({
  name: String,
  email: String,
  password: String,
  dateOfBirth: Date,
  verified: boolean,
});

const User = mongoose.model("User", UserSchema);

module.exports = User;

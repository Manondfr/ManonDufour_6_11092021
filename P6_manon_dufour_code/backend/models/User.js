const mongoose = require('mongoose');
const uniqueValidator = require('mongoose-unique-validator');
const mongooseHidden = require('mongoose-hidden')();

const userSchema = mongoose.Schema({
  email: { type: String, hide: true, required: true, unique: true },
  password: { type: String, required: true }
});

userSchema.plugin(uniqueValidator);
userSchema.plugin(mongooseHidden);

module.exports = mongoose.model('User', userSchema);
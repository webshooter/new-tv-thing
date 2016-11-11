"use strict";

let mongoose = require("mongoose");
let bcrypt = require("bcryptjs");
let Schema = mongoose.Schema;

let UserSchema = new Schema({

  username: {
    type: String,
    unique: true,
    required: true
  },

  password: {
    type: String,
    required: true
  }

}, {
  toObject: {
    virtuals: true
  }, toJSON: {
    virtuals: true
  }
});

UserSchema.pre("save", (next) => {
  let that = this;
  let user = that;

  if (this.isModified("password") || this.isNew) {
    return bcrypt.genSalt(10, (saltErr, salt) => {
      if (saltErr) {
        return next(saltErr);
      }
      return bcrypt.hash(user.password, salt, (hashErr, hash) => {
        if (hashErr) {
          return next(hashErr);
        }
        user.password = hash;
        return next();
      });
    });
  }
  return next();
});

UserSchema.methods.comparePassword = (passw, cb) => {
  bcrypt.compare(passw, this.password, (err, isMatch) => {
    if (err) {
      return cb(err);
    }
    return cb(null, isMatch);
  });
};

module.exports = mongoose.model("User", UserSchema);

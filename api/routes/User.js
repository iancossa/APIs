const express = require("express");
const router = express.Router();

//mongodb user model
const User = require("./../models/User");

//mongodb userVerification model
const UserVerification = require("./../models/UserVerification");

//password handler
const bcrypt = require("bcrypt");

//email handler
const nodemailer = require("nodemailer");

//unique string
const { v4: uuidv4 } = require("uuid");
const { errorMonitor } = require("nodemailer/lib/xoauth2");

//env variables
require("dotenv").config();

//nodemailer functionalities
let transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.AUTH_EMAIL,
    pass: process.env.AUTH_PASS, // Fixed typo
  },
});

//testing the transporter
transporter.verify((error, success) => {
  if (error) {
    console.log(error);
  } else {
    console.log("Ready for messages");
  }
});

//Sign Up
router.post("/signup", (req, res) => {
  // Fixed route name
  let { name, email, password, dateOfBirth } = req.body;
  name = name.trim();
  email = email.trim();
  password = password.trim();
  dateOfBirth = dateOfBirth.trim();

  if (name === "" || email === "" || password === "" || dateOfBirth === "") {
    res.json({
      status: "FAILED",
      message: "Empty input fields!",
    });
  } else if (!/^[a-zA-Z]*$/.test(name)) {
    res.json({
      status: "FAILED",
      message: "Invalid name entered",
    });
  } else if (!/^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$/.test(email)) {
    // Fixed regex
    res.json({
      status: "FAILED",
      message: "Invalid email entered",
    });
  } else if (isNaN(new Date(dateOfBirth).getTime())) {
    // Fixed date validation
    res.json({
      status: "FAILED",
      message: "Invalid date of birth entered",
    });
  } else if (password.length < 8) {
    res.json({
      status: "FAILED",
      message: "Password is too short!",
    });
  } else {
    //check if user already exists
    User.find({ email })
      .then((result) => {
        if (result.length) {
          res.json({
            status: "FAILED",
            message: "User with the provided email already exists",
          });
        } else {
          //password handling
          const saltRounds = 10;
          bcrypt
            .hash(password, saltRounds)
            .then((hashedPassword) => {
              const newUser = new User({
                name,
                email,
                password: hashedPassword,
                dateOfBirth,
                verified: false,
              });

              newUser
                .save()
                .then((result) => {
                  sendVerificationEmail(result); // Fixed function call
                })
                .catch((err) => {
                  res.json({
                    status: "FAILED",
                    message: "An error occurred while saving user account!",
                  });
                });
            })
            .catch((err) => {
              res.json({
                status: "FAILED",
                message: "An error occurred while hashing the password!",
              });
            });
        }
      })
      .catch((err) => {
        res.json({
          status: "FAILED",
          message: "An error occurred while checking for existing user!",
        });
      });
  }
});

//send verification email
const sendVerificationEmail = ({ _id, email }, res) => {
  //url to be used in the email
  const currentUrl = "http://localhost:5000/";
  const uniqueString = uuidv4() + _id;

  //mail options
  const mailOption = {
    from: process.env.AUTH_EMAIL,
    to: email,
    subject: "Verify Your Email",
    html: '<p>Verify your email Adrress to complete the signup and login into your account</p><p><b>This link expires in 8hrs</b></p><p>Press <a href =${currentUrl + "user/verify/"+ _id + "/" + uniqueString }here</a>to proceed></p>',
  };
  //?!doubts: this html script over thre on the link it should with other color, is it working ?!?
};

//hash the unique string
const saltRounds = 10;
bcrypt
  .hash(uniqueString, saltRounds)
  .then((hashedUniqueString) => {
    //set values in userVerification collection
    const newVerification = newVerification({
      userId: _id,
      uniqueString: hashedUniqueString,
      createdAt: Date.now(),
      expiresAt: Date.now() + 28800000,
    });
    newVerification
      .save()
      .then(() => {
        transporter.sendMail(mailOption).then.catch((error) => {
          //email sent and verification record saved
          res.json({
            status: "PENDING",
            message: "Verification email sent",
          });
        });
      })
      .catch((error) => {
        console.log(error);
        res.json({
          status: "FAILED",
          message: "Oops,couldn't save verification email data",
        });
      });
  })
  .catch(() => {
    res.json({
      status: "FAILED",
      message: "An error occured while hashing email data!",
    });
  });

//Sign In
router.post("/signin", (req, res) => {
  let { email, password } = req.body;
  email = email.trim();
  password = password.trim();

  if (email === "" || password === "") {
    res.json({
      status: "FAILED",
      message: "Empty credentials supplied",
    });
  } else {
    User.find({ email })
      .then((data) => {
        if (data.length) {
          const hashedPassword = data[0].password;
          bcrypt
            .compare(password, hashedPassword)
            .then((result) => {
              if (result) {
                res.json({
                  status: "SUCCESS",
                  message: "Signin successful",
                  data: data,
                });
              } else {
                res.json({
                  status: "FAILED",
                  message: "Invalid password entered!",
                });
              }
            })
            .catch((err) => {
              res.json({
                status: "FAILED",
                message: "An error occurred while comparing passwords",
              });
            });
        } else {
          res.json({
            status: "FAILED",
            message: "Invalid credentials entered!",
          });
        }
      })
      .catch((err) => {
        res.json({
          status: "FAILED",
          message: "An error occurred while checking for existing user",
        });
      });
  }
});

module.exports = router;

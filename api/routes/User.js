const express = require("express");
const router = express.Router();

//mongodb user model
const User = require("./../../models/Usuario");

//mongodb userVerification model
const UserVerification = require("./../../models/Verification");

//mongodb ResetPassword model
const ResetPassword = require("./../../models/ResetPassword");

//password handler
const bcrypt = require("bcrypt");

//email handler
const nodemailer = require("nodemailer");

//unique string
const { v4: uuidv4 } = require("uuid");
const { errorMonitor } = require("nodemailer/lib/xoauth2");

//path for static verified page
const path = require("path");
const { error } = require("console");
const { verify } = require("crypto");

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
    html: `<p>Verify your email Adrress to complete the signup and login into your account</p><p><b>This link expires in 8hrs</b></p><p>Press <a href =${
      currentUrl + "user/verify/" + _id + "/" + uniqueString
    }here</a>to proceed></p>`,
  };
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

//verify email
router.get("", (req, res) => {
  let { userId, uniqueString } = req.params;

  UserVerification.find({ userId })
    .then((result) => {
      if (result.length > 0) {
        //user verification record exists, then we proceed
        const { expiresAt } = result[0];
        const hashedUniqueString = result[0].uniqueString;

        //checking for expired unique string
        if (expiresAt < Date.now()) {
          //record has expired so we can delete it
          UserVerification.deleteOne({ userId })
            .then((result) => {
              User.deleteOne({ _id: userId })
                .then(() => {
                  let message = "Link as expired. Please sign up again.";
                  res.redirect("/user/verified/error=true&messages=${message}");
                })
                .catch((error) => {
                  console.log(error);
                  let message =
                    "Clearing user with expired unique string failed";
                  res.redirect("/user/verified/error=true&messages=${message}");
                });
            })
            .catch((error) => {
              console.log(error);
              let message =
                "An erro occured while clearing expires user verification record";
              res.redirect("/user/verified/error=true&messages=${message}");
            });
        } else {
          //valid record exists so we validate the user string
          //1st compare the hashed unique string
          bcrypt
            .compare(uniqueString, hashedUniqueString)
            .then((result) => {
              if (result) {
                //strings match
                User.updateOne({ _id: userId }, { verified: true }).then(() => {
                  UserVerification.deleteOne({ userId })
                    .then(() => {
                      res.sendFile(
                        path.join(__dirname, "./../views/verifiedproof.html")
                      );
                    })
                    .catch((error) => {
                      console.log(error);
                      let message =
                        "An error occured while finalizing verification.";
                      res.redirect(
                        "/user/verified/error=true&messages=${message}"
                      );
                    })
                    .catch((error) => {
                      console.log(error);
                      let message =
                        "An error occured while updating user record to show verified.";
                      res.redirect(
                        "/user/verified/error=true&messages=${message}"
                      );
                    });
                });
              } else {
                //existing record but incorrect verification details passed
                let message =
                  "Invalid verification details passed. Check your inbox.";
                res.redirect("/user/verified/error=true&messages=${message}");
              }
            })
            .catch((error) => {
              let message = "An error occured while comparing unique strings.";
              res.redirect("/user/verified/error=true&messages=${message}");
            });
        }
      } else {
        //user verification record doesn't exist
        let message =
          "Account record record doesn't exist or have been verified already . Please sign up or log in.";
        res.redirect("/user/verified/error=true&messages=${message}");
      }
    })
    .catch((error) => {
      console.log(error);
      let message =
        "An erro occured while checking for existing user verification record!";
      res.redirect("/user/verified/error=true&messages=${message}");
    });
});

//Verified  proof page route
router.get("/verified", (req, res) => {
  res.sendFile(path.join(__dirname, "./../views/verifiedproof.html"));
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
          //User exists

          //check if user is verified
          if (!data[0].verified) {
            res.json({
              status: "Failed",
              message: "Email hasn't been verified yet.Check your inbox.",
            });
          } else {
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
          }
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

//Password reset
router.post("/requestResetPassword", (req, res) => {
  const { email, redirectUrl } = req.body;

  User.find({ email }),
    then((data) => {
      if (data.length) {
        //user exists

        //check if user is verified
        if (!data[0].verified) {
          res.json({
            status: "Email hasn't been verified yet. Check your inbox",
          });
        } else {
          //proceed with email to reset password
          sendResetEmail(data[0], redirectUrl, res);
        }
      } else {
        res.json({
          status: "FAILED",
          message: "No account with the supplied email exists",
        });
      }
    }).catch((error) => {
      console.log(error);
      res.json({
        status: "FAILED",
        message: "An error occurred while checking for existing user",
      });
    });
});

//send password reset

const sendResetEmail = ({ _id, email }, redirectUrl, res) => {
  const resetString = uuidv4 + _id;

  //First, we clear all existing records
  PasswordReset.deleteMany({ userId: _id })
    .then((result) => {
      //Reset records deleted successfully
      //Now we send the email

      //mail options
      const mailOption = {
        from: process.env.AUTH_EMAIL,
        to: email,
        subject: "Reset Password",
        html: `<p>We heard that you lost your password</p><p>Use the link bellow to reset your password</p><p><b>This link expires in 60 minutes</b></p><p>Press <a href =${
          currentUrl + "/" + _id + "/" + resetString
        }here</a>to proceed></p>`,
      };

      //hash the reset string
      const saltRounds = 10;
      bcrypt
        .hash(resetString, saltRounds)
        .then((hashedResetString) => {
          //set values in password reset collection
          const newPassswordReset = new PasswordReset({
            userId: _id,
            resetString: hashedResetString,
            createdAt: Date.now(),
            expiredAt: Date.now() + 3600000,
          });

          newPasswordReset.save().then().catch();
        })
        .catch((error) => {
          console.log(error);
          res.json({
            status: "FAILED",
            message: "An error occured while hashing  the password reset data!",
          });
        });
    })
    .catch((error) => {
      //error while clearing existing records
      console.log(error);
      res.json({
        status: "FAILED",
        message: "Clearing existing password reset records failed!",
      });
    });
};

module.exports = router;

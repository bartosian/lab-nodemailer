const express = require("express");
const passport = require('passport');
const router = express.Router();
const User = require("../models/User");
const nodemailer = require('nodemailer');
// Bcrypt to encrypt passwords
const bcrypt = require("bcrypt");
const bcryptSalt = 10;



router.get("/login", (req, res, next) => {
  res.render("auth/login", { "message": req.flash("error") });
});

router.post("/login", passport.authenticate("local", {
  successRedirect: "/",
  failureRedirect: "/auth/login",
  failureFlash: true,
  passReqToCallback: true
}));

router.get("/signup", (req, res, next) => {
  res.render("auth/signup");
});

router.post("/signup", (req, res, next) => {
  const username = req.body.username;
  const password = req.body.password;
  const email    = req.body.email;

  if (username === "" || password === "" || email === "" ) {
    res.render("auth/signup", { message: "Indicate username,password and email!" });
    return;
  }

  User.findOne({ username }, "username", (err, user) => {
    if (user !== null) {
      res.render("auth/signup", { message: "The username already exists" });
      return;
    }

    const salt = bcrypt.genSaltSync(bcryptSalt);
    const hashPass = bcrypt.hashSync(password, salt);
    const confirmationCode = bcrypt.hashSync(username, salt);

    const newUser = new User({
      username,
      password: hashPass,
      confirmationCode,
      email
    });

    newUser.save()
    .then(() => {

        let transporter = nodemailer.createTransport({
            service: 'Gmail',
            auth: {
                user: process.env.EMAIL,
                pass: process.env.PASSWORD
            }
        });

        transporter.sendMail({
            from: "IRONHACK MEDIA SERVICE",
            to: email,
            subject: "Activation account.",
            text: "Hi user, to activate your account you need to click this link.",
            html: `<a>http://localhost:3000/auth/confirm/${username}</a>`
        }).then()
            .catch(error => console.log(error));
    })
    .catch(err => {
      res.render("auth/signup", { message: "Something went wrong" });
    })
  });
});

router.get("/confirm/:confirmCode", (req, res) => {
  const confirmationCode = req.params.confirmCode;
  if(confirmationCode === req.user.confirmationCode) {
    console.log('COOL!');
  }
});

router.get("/logout", (req, res) => {
  req.logout();
  res.redirect("/");
});

module.exports = router;

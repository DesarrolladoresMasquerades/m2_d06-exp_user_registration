const express = require("express");
const User = require("../models/User.model");
const router = express.Router();
const saltRounds = 5;
const bcrypt = require("bcrypt");

router
  .route("/signup")
  .get((req, res) => {
    res.render("signup");
  })
  .post((req, res) => {
    const username = req.body.username;
    const password = req.body.password;

    // Check the form is NOT empty
    if (!username || !password) {
      res.render("signup", { errorMessage: "All filds are required" });
    }

    User.find({ username }).then((user) => {
      if (user) {
        res.render("signup", { errorMessage: "User already taken!" });
      }

      const salt = bcrypt.genSaltSync(saltRounds);
      const hashedPwd = bcrypt.hashSync(password, salt);

      User.create({ username, password: hashedPwd });
    });
  });

router.get("/login", (req, res) => {
  res.render("login");
});

router.get("/profile", (req, res) => {
  res.render("profile");
});

module.exports = router;

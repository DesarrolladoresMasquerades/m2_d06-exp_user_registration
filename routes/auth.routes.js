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

    User.findOne({ username }).then((user) => {
      if (user && user.username) {
        res.render("signup", { errorMessage: "User already taken!" });
        throw new Error("Validation error");
      }

      const salt = bcrypt.genSaltSync(saltRounds);
      const hashedPwd = bcrypt.hashSync(password, salt);

      User.create({ username, password: hashedPwd }).then(() =>
        res.redirect("/index")
      );
    });
  });

router
  .route("/login")
  .get((req, res) => {
    res.render("login");
  })
  .post((req, res) => {
    const username = req.body.username;
    const password = req.body.password;

    if (!username || !password) {
      res.render("login", { errorMessage: "All filds are required" });
      throw new Error("Validation error");
    }

    User.findOne({ username })
      .then((user) => {
        if (!user) {
          res.render("login", { errorMessage: "Incorrect credentials!" });
          throw new Error("Validation error");
        }

        const isPwCorrect = bcrypt.compareSync(password, user.password);

        if (isPwCorrect) {
          req.session.currentUserId = user._id;
          res.redirect("/profile");
        } else {
          res.render("login", { errorMessage: "Incorrect credentials!" });
        }
      })
      .catch((error) => console.log(error));
  });

router.get("/profile", (req, res) => {
  const id = req.session.currentUserId;
  User.findById(id)
    .then((user) => res.render("/profile", user))
    .catch(err=>console.log(err));
});

router.get("/logout", ()=>{
  req.session.destroy((err)=>res.redirect("/")
  )
})

module.exports = router;

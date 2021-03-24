require("dotenv").config();

const express = require("express");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate = require("mongoose-findorcreate");

const app = express();

app.set("view engine", "ejs");
app.use(express.static("public"));
app.use(express.urlencoded({ extended: true })); // to support URL-encoded bodies

app.use(
  session({
    secret: "get from .env",
    resave: false,
    saveUninitialized: false,
  })
);
app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB", { useNewUrlParser: true, useUnifiedTopology: true, useCreateIndex: true });

// Schema
const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  secret: String,
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

// Model
const User = new mongoose.model("User", userSchema);
passport.use(User.createStrategy());

// Serialize and deserialize user using passport
passport.serializeUser(function (user, done) {
  done(null, user.id);
});
passport.deserializeUser(function (id, done) {
  User.findById(id, function (err, user) {
    done(err, user);
  });
});

// Google Auth
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/secrets",
      // userProfileURL: "https://www.google.com/oauth2/v3/userinfo",
    },
    function (accessToken, refreshToken, profile, done) {
      console.log(profile);
      User.findOrCreate({ googleId: profile.id }, function (err, user) {
        return done(err, user);
      });
    }
  )
);

// Facebook Auth
/* Coming up soon */

// Route
app.get("/", (req, res) => {
  res.render("home");
});

app.get("/auth/google", passport.authenticate("google", { scope: ["profile"] }));

app.get("/auth/google/secrets", passport.authenticate("google", { failureRedirect: "/login" }), (req, res) => {
  // Successful authentication, redirect home.
  res.redirect("/secrets");
});

app
  .route("/register")
  .get((req, res) => {
    if (req.isAuthenticated()) res.redirect("/secrets");
    else res.render("register");
  })
  .post((req, res) => {
    User.register({ username: req.body.username }, req.body.password, (err, user) => {
      if (err) {
        console.log(err);
        res.render("/register");
      } else {
        passport.authenticate("local")(req, res, () => {
          res.redirect("/secrets");
        });
      }
    });
  });

app
  .route("/login")
  .get((req, res) => {
    if (req.isAuthenticated()) res.redirect("/secrets");
    else res.render("login");
  })
  .post((req, res) => {
    const user = new User({
      username: req.body.username,
      password: req.body.password,
    });

    req.login(user, (err) => {
      if (err) {
        console.log(err);
      } else {
        passport.authenticate("local")(req, res, () => {
          res.redirect("/secrets");
        });
      }
    });
  });

app.get("/logout", (req, res) => {
  req.logout();
  res.redirect("/");
});

app.get("/secrets", (req, res) => {
  if (req.isAuthenticated()) {
    User.find({ secret: { $exists: true } }, (err, result) => {
      if (err) console.log(err);
      else res.render("secrets", { userSecret: result });
    });
  } else res.redirect("/login");
});

app
  .route("/submit")
  .get((req, res) => {
    if (req.isAuthenticated()) res.sender("submit");
    else res.redirect("login");
  })
  .post((req, res) => {
    const submittedSecret = req.body.secret;
    User.findById(req.user.id, (err, result) => {
      if (err) console.log(err);
      else {
        if (result) {
          result.secret = submittedSecret;
          result.save(() => res.redirect("/secrets"));
        }
      }
    });
  });

app.listen(3000, () => console.log("Server started at port 3000"));

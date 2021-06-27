//                                                <Authentication and Security>
//Level 1 - UserName And Password
//level 2 - mongoose-encryption, using env variables
//Level 3 - Hashing Password -md5
//Level 4 - Salting and Hashing password using bcrypt
require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');

const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');

const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');

// const bcrypt = require('bcrypt');
// const saltRounds = 10;

// const md5 = require('md5');

// const encrypt = require('mongoose-encryption');

const app = express();
app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
  extended: true
}));

//cookie creation
app.use(session({
  secret: 'This is a secret',
  resave: false,
  saveUninitialized: false
}));

//initialize the passport(Authentication for Nodejs) to manage session
app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB", {
  useUnifiedTopology: true,
  useNewUrlParser: true
});
mongoose.set("useCreateIndex", true);

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  secret: String
});

//Carries out registration and login process into the db
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

// var secret = process.env.SOME_LONG_UNGUESSABLE_STRING;
// userSchema.plugin(encrypt, { secret: secret ,  encryptedFields: ['password']});

const User = mongoose.model("User", userSchema);

//for serialisation and de-serialisation of the cookie
passport.use(User.createStrategy());
passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);

    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/", function(req, res) {
  res.render("home");
});

app.get("/auth/google",
  passport.authenticate('google', { scope: ["profile"] })
);
app.get("/auth/google/secrets",
  passport.authenticate('google', { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect to secrets.
    res.redirect("/secrets");
  });

app.get("/logout",function(req,res){
  req.logout();
  res.redirect("/");
});

// app.get("/secrets", function(req, res) {
//   if (req.isAuthenticated()) {
//     res.render("secrets");
//   } else {
//     res.render("login");
//   }
// });
app.get("/secrets", function(req, res){
  User.find({"secret": {$ne: null}}, function(err, foundUsers){
    if (err){
      console.log(err);
    } else {
      if (foundUsers) {
        res.render("secrets", {usersWithSecrets: foundUsers});
      }
    }
  });
});

app.get("/submit", function(req, res){
  if (req.isAuthenticated()){
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});
app.post("/submit", function(req, res){
  const submittedSecret = req.body.secret;

//Once the user is authenticated and their session gets saved, their user details are saved to req.user.
  // console.log(req.user.id);

  User.findById(req.user.id, function(err, foundUser){
    if (err) {
      console.log(err);
    } else {
      if (foundUser) {
        foundUser.secret = submittedSecret;
        foundUser.save(function(){
          res.redirect("/secrets");
        });
      }
    }
  });
});
app.route("/register")
  .get(function(req, res) {
    res.render("register");
  })
  .post(function(req, res) {

    User.register({
      username: req.body.username
    }, req.body.password, function(err, user) {
      if (err) {
        console.log(err);
        res.redirect("/register");
      } else {
        passport.authenticate("local")(req, res, function() {
          res.redirect("/secrets");
        });
      }
    })
    // const email = req.body.username;
    // const password = req.body.password;
    // bcrypt.hash(password, saltRounds, function(err, hash) {
    //   const newUser = new User({
    //     email: email,
    //     password: hash
    //   });
    //
    //   newUser.save(function(err) {
    //     if (!err) {
    //       res.render("secrets");
    //     } else {
    //       res.send(err);
    //     }
    //   });
    // });
  });

app.route("/login")
  .get(function(req, res) {
    res.render("login");
  })
  .post(
    function(req, res) {

      const user = new User({
        email: req.body.username,
        password: req.body.password
      });
//       passport.serializeUser(function(user, done) {
//   done(null, user);
// });
//
// passport.deserializeUser(function(user, done) {
//   done(null, user);
// });

      req.login(user, function(err) {
        if (err) {
          console.log(err);
        }else{
          passport.authenticate("local")(req,res,function(){
            res.redirect("/secrets");
          });
        }
      });
      //   const email = req.body.username;
      //   const password = req.body.password;
      //
      //   User.findOne({
      //     email: email
      //   }, function(err, foundItem) {
      //     if (!err) {
      //       if (foundItem) {
      //         bcrypt.compare(password, foundItem.password, function(err, result) {
      //           if (result == true) {
      //             res.render("secrets");
      //           } else {
      //             res.render("login");
      //             // alert('Check your credentials!');
      //           }
      //         });
      //       } else {
      //         res.render("register");
      //         // alert("New User?? Please Register to Access Secrets");
      //       }
      //     } else {
      //       res.send(err);
      //     }
      // });
    });


app.listen(3000, function() {
  console.log("Server started on port 3000");
});

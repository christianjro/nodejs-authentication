require('dotenv').config();

const express = require("express");
const path = require("path");
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const mongoose = require("mongoose");
const Schema = mongoose.Schema;

const mongoDb = process.env.DB_STRING;
mongoose.connect(mongoDb, { useUnifiedTopology: true, useNewUrlParser: true });
const db = mongoose.connection;
db.on("error", console.error.bind(console, "mongo connection error"));

const User = mongoose.model(
    "User",
    new Schema({
        username: { type: String, required: true },
        password: { type: String, required: true }
    })
);

const app = express();
app.set("views", __dirname);
app.set("view engine", "ejs");

app.use(session({ 
    secret: process.env.SECRET, 
    resave: false, 
    saveUninitialized: true
}));

// Authentication: 3 functions and app.post for the /log-in path
// Function 1: setting up the LocalStrategy 
passport.use(
    new LocalStrategy((username, password, done) => {
        User.findOne({username: username}, (err, user) => {
            if (err) {
                return done(err);
            }
            if (!user) {
                return done(null, false, {message: "Incorrect username"});
            }
            if (user.password !== password) {
                return done(null, false, {message: "Incorrect password"});
            }
            return done(null, user);
        });
    })
);

// Function 2 & 3: Sessions and Serialization
passport.serializeUser(function(user, done) {
    done(null, user.id);
});

passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
        done(err, user);
    });
});

app.use(passport.initialize());
app.use(passport.session());
app.use(express.urlencoded({ extend: false}));

app.get("/", (req, res) => {
    res.render("index")
});

app.get("/sign-up", (req, res) => {
    res.render("sign-up-form")
});

app.post("/sign-up", (req, res, next) => {
    const user = new User({
        username: req.body.username,
        password: req.body.password
    }).save(err => {
        if (err) {
            return next(err);
        }
        res.redirect("/");
    });
});

app.post(
    "/log-in", 
    passport.authenticate("local", {
        successRedirect: "/",
        failureRedirect: "/"
    })
);


app.listen(3000, () => console.log("app listening on port 3000!"));

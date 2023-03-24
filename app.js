require('dotenv').config();

const express = require("express");
const path = require("path");
const session = require("express-session");
const flash = require("connect-flash");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const mongoose = require("mongoose");
const { rmSync } = require('fs');
const bcrypt = require('bcryptjs');
const Schema = mongoose.Schema;

// Connect to MongoDB
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

app.use(flash());

// Authentication: 3 functions and app.post for the /log-in path
// Function 1: setting up the LocalStrategy 
passport.use(
    new LocalStrategy(async(username, password, done) => {
        try {
            const user = await User.findOne({username: username});
            if (!user) {
                return done(null, false, {message: "Incorrect username"});
            };

            bcrypt.compare(password, user.password, (err, res) => {
                if (res) {
                    return done(null, user);
                } else {
                    return done(null, false, {message: "Incorrect password"});
                };
            });

        } catch(err) {
            return done(err);
        };
    })
)

// Function 2 & 3: Sessions and Serialization
passport.serializeUser(function(user, done) {
    done(null, user.id);
});

passport.deserializeUser(async function(id, done) {
    try {
        const user = await User.findById(id);
        done(null, user);
    } catch(err) {
        done(err);
    }
})

app.use(passport.initialize());
app.use(passport.session());
app.use(express.urlencoded({ extend: false}));

// // This is a middleware function that lets you have access to the 
// // currentUser variable in all of our views without manually passing into the controllers.
// app.use(function(req, res, next) {
//     res.locals.currentUser = req.user;
//     next();
// });

app.get("/", (req, res) => {
    res.render("index", {user: req.user, message: req.flash("error")});
});

app.get("/sign-up", (req, res) => {
    res.render("sign-up-form")
});

app.post("/sign-up", async (req, res, next) => {
    try {
        const user = new User({
            username: req.body.username,
            password: req.body.password
        });
        bcrypt.hash(user.password, 10, async (err, hashedPassword) => {
            if(err) {
                return next(err);
            } else {
                user.password = hashedPassword;
                const result = await user.save();
                res.redirect("/");
            }
        })
    } catch(err) {
        return next(err)
    }
});

app.post(
    "/log-in", 
    passport.authenticate("local", {
        successRedirect: "/",
        failureRedirect: "/",
        failureFlash: true
    }),
);

app.get("/log-out", (req, res) => {
    req.logout(function(err) {
        if (err) {
            return next(err);
        }
        res.redirect("/");
    });
});


app.listen(3000, () => console.log("app listening on port 3000!"));

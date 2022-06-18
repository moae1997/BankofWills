
// required modules ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ 

require("dotenv").config();
const express = require("express");
const body = require("body-parser");
const mongoose = require("mongoose");
const _ = require("lodash");
const ejs = require("ejs");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const encrypt = require("mongoose-encryption");
const local = require("passport-local");
const MongoStore = require("connect-mongo");
const nodemailer = require('nodemailer');
const jwt = require("jsonwebtoken");
const {check, validationResult} = require("express-validator");
const app = express();


// mongoose connection ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

const connect = mongoose.connect(process.env.Mongo);
const willSchema = new mongoose.Schema({
    username: {
        type: String,
    },
    name: {
        type: String,
        required: true
    },
    user: {
        type: String,
    },
    will: Array
});

willSchema.plugin(encrypt, {secret: process.env.SECRETS, encryptedFields: ["will"]});
willSchema.plugin(passportLocalMongoose, {hashField: "password", populateFields: ["password"]});
const User = mongoose.model("User", willSchema);
const Will = mongoose.model("Will", willSchema);


app.use(session({

    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: true,
    store: MongoStore.create({
        mongoUrl: process.env.mongo2,
        dbName: "willDB",
        collectionName: "sessions"
    }),
    cookie: {
        maxAge: 100 * 60 * 60 * 24
    }
}));

passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());
passport.use(new local(User.authenticate()));
app.set("view engine", "ejs");
app.use(express.json());
app.use(body.urlencoded({extended: true}));
app.use(express.static("public"));
app.use(passport.initialize());
app.use(passport.session());




// Get routes +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++


app.get("/",checkNotAuthenticated, function(req, res) {
    res.render("main");
});
app.get("/login", checkNotAuthenticated, function(req, res) {
    res.render("login");  
});
app.get("/register", checkNotAuthenticated, function(req, res) {
    res.render("register");
});
app.get("/bank", isLoggedIn, function(req, res) {
    
    Will.findOne({user: req.user.username}, function(err, user){
        res.render("bank", {
            Willlist: user.will,
            user: user.name
        });

    });
    
});
app.get("/forgotPassword", checkNotAuthenticated, function(req, res) {
    res.render("setpassword");
});
app.get("/changePassword", isLoggedIn, function(req, res){
    res.render("changepassword");
});
app.get("/logout", function(req, res){
    req.logOut(function(err){
        res.redirect("/");
    });
});
app.get("/newpass/:token/:username", checkNotAuthenticated, function(req, res){
    const {token, username} = req.params;

    User.findByUsername(username, function(err, user){
        if (user == null) {
            res.send("<h1>An error occured please try again</h1>");
            return;
        } else if (username === user.username) {
            const secret = process.env.JWT + user.password;
           jwt.verify(token, secret, function(err, code){
                if (code == null) {
                    res.redirect("/"); 
                    return; 
                } else { 
                res.render("newpass");
                }
            });
        } else {
            res.redirect("/");
        }
    });
});
app.get("/remove", isLoggedIn, function(req, res){
    res.render("remove");
});


// Post routes +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

app.post('/register', check("username", "Please Enter a Valid Email Address.").trim().normalizeEmail().isEmail(), check("password", "Password must be at least 8 characters").isLength({ min:8}), function(req,res){
    
    const error = validationResult(req);
    if(!error.isEmpty()) {
        const err = error.array();
        const e = [];
        err.forEach(function(er){
            e.push(er.msg);
        });
        res.render("register", {alert: e});
        return;
    } else {
    User.findByUsername(req.body.username, function(err, user){
        if(user != null) {
            res.status(401).json({error: "User Already Taken, please enter a different User email"});
            return;
        } else {
        User.register({username:req.body.username, name:req.body.name}, req.body.password, function(err, user){
            passport.authenticate("local")(req, res, function(){
                
                const will = new Will({
                    name: req.body.name,
                    user: req.body.username
                });
                will.save();
                res.render("login", {alert: ["Successfully signed up for Will Bank!"]});
            });
        });
    }
    }); 
   
}
});    
    
app.post("/login", passport.authenticate("local", {
    successRedirect: "/bank",
    failureRedirect: "/login"
}), function(req, res){

});


app.post("/will", function(req, res) {
    const will = req.body.myWill;
    const user = req.user.username;
    
    Will.findOne({user: user}, function(err, user){
        user.will.push(will);
        user.save();
        res.redirect("/bank");
    })
    
});

app.post("/delete", function(req, res){
   Will.findOneAndRemove({user: req.user.username}, function(err){
    const will = new Will({
        user: req.user.username,
        name: req.user.name
    });
            will.save();
            res.redirect("/bank");
   });
  
});

app.post("/passwordchange", check("newpass", "Password must be at least 8 characters").isLength({min:8}), function(req, res){

    const error = validationResult(req);
    if(!error.isEmpty()) {
        const err = error.array();
        const e = [];
        err.forEach(function(er){
            e.push(er.msg);
        });
        res.render("changepassword", {alert: e});
        return;
    } else {
    User.findByUsername(req.user.username, function(err, user){
        if (user == null){
            res.status(401).json({errors: "Sorry, please try again"});
        }
        user.changePassword(req.body.oldpass, req.body.newpass, function(err, info){
           if (info === undefined) {
               res.status(401).json({errors: "Sorry, please try again"});
               return;
           } else {
            user.save();
            res.render("changepassword", {alert: ["Successfully changed your password"]});
           }           
        });
    });
}
});
app.post("/passwordset", function(req, res){
    
    const useremail = req.body.setpassemail;

    User.findByUsername(useremail, function(err, user){
        if (user == null) {
            res.send("<h1>No user was found with that email please try again</h1>");
            return;
        } else if (useremail === user.username) {
            const secret = process.env.JWT + user.password;
            const payload = {id: user.id, email: user.username};
            const token = jwt.sign(payload, secret, {expiresIn: "10m"});

            const link = `https://willbank12.herokuapp.com/newpass/${token}/${user.username}`;

            const transporter = nodemailer.createTransport({
                service: 'gmail',
                auth: {
                  user: process.env.email,
                  pass: process.env.pass
                }
              });
              
              const mailOptions = {
                from: process.env.emails,
                to: user.username,
                subject: 'Password Reset For Will Bank!',
                text: link
              };
              
              transporter.sendMail(mailOptions, function(error, info){
                  res.render("login", {alert: ["Email sent Successfully"]});
              });
            } else {
                res.redirect("/login");
            }    
    });
});
app.post("/newpass/:token/:username", check("password", "Password needs to be at least 8 characters").isLength({min:8}), function(req, res){

    const error = validationResult(req);
    if(!error.isEmpty()) {
        const err = error.array();
        const e = [];
        err.forEach(function(er){
            e.push(er.msg);
        });
        res.render("newpass", {alert: e});
        return;
    } else {
    const {token, username} = req.params;
    User.findByUsername(username, function(err, user){
        if (user == null) {
            res.send("<h1>An error occured please try again</h1>");
            return;
        } else if (username === user.username) {
           try {
            const secret = process.env.JWT + user.password;
            const payload = jwt.verify(token, secret);
            user.setPassword(req.body.password, function(err){
                user.save();
            });
            res.render("login", {alert: ["Successfully set your password"]});
           } catch (e) {
               console.log(e);
           }

        }
    
    });
    } 
});
app.post("/remove", function(req, res){

    User.findByUsername(req.body.removeemail, function(err, user){
        if(user == null) {
            res.status(401).json({error: "No User With That User Email, please try again"});
            return;
        } else if (user.username === req.body.removeemail){
            User.findByIdAndDelete(user.id, function(err, info){
                Will.findOneAndRemove({user: req.body.removeemail}, function(err, info){
                    res.render("remove", {alert: ["Successfully deleted your account"]});
                });
            });
        }
    });
});
// Middleware ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
function isLoggedIn(req,res,next) {
    if(req.isAuthenticated()){
        next();
        return;
    }
    res.redirect("/login");
}
function checkNotAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
      return res.redirect('/bank');
    }
    next()
  }
// Server ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
app.listen(process.env.PORT, function(req, res) {
    console.log("Welcome to the Bank of Wills!");
});

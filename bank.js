
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
const crypto = require("crypto");
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
    will: Array,
    emailToken: String,
    isVerified: Boolean,
    draft: String
});

willSchema.plugin(encrypt, {secret: process.env.SECRETS, encryptedFields: ["will", "draft"]});
willSchema.plugin(passportLocalMongoose, {hashField: "password", populateFields: ["password"]});
const User = mongoose.model("User", willSchema);
const Will = mongoose.model("Will", willSchema);


app.use(session({

    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: true,
    rolling: true,
    store: MongoStore.create({
        mongoUrl: process.env.mongo2,
        dbName: "willDB",
        collectionName: "sessions"
    }),
    cookie: {
        maxAge: 60000 * 15
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
app.get("/bank", demo2, isLoggedIn, function(req, res) {

    Will.findOne({user: req.user.username}, function(err, user){
            return res.render("bank", {
                Willlist: user.will,
                user: user.name,
                draft: user.draft
            });
     });    
});
app.get("/forgotPassword", checkNotAuthenticated, function(req, res) {
    res.render("setpassword");
});
app.get("/changePassword", demo4, isLoggedIn, function(req, res){
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
app.get("/remove", demo3, isLoggedIn, function(req, res){
    res.render("remove");
});
app.get("/emailv", function(req, res){
    const token = req.query.token;
    User.findOne({emailToken: token}, function(err, user){
            if (user) {
                user.emailToken = null;
                user.isVerified = true;
                user.save();
                res.send("<h1>Thank you for verifying your email, you can login now</h1>");
                return;
            } else {
                res.send("<h1>Opps... Looks like there was an error plaese retry the link in your email</h1>");
            }   
    });
});

// Post routes +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

app.post('/register', demo, check("username", "Please Enter a Valid Email Address.").trim().normalizeEmail().isEmail(), check("password", "Password must be at least 8 characters").isLength({ min:8}), function(req,res){
    
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
        User.register({username:req.body.username, name:req.body.name, emailToken: crypto.randomBytes(64).toString("hex"), isVerified: false}, req.body.password, function(err, user){
            
            const will = new Will({
                name: user.name,
                user: user.username,
            });
            will.save();

            const token = user.emailToken;
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
                subject: 'Verify Email For Will Bank!',
                text: `Please copy paste the link to verify your email
                http://${req.headers.host}/emailv?token=${token}`,
                html: `<h1>Thank you for signing up for the BankofWills!</h1>
                <p>Please click the link to verify your email</p>
                <a href="http://${req.headers.host}/emailv?token=${token}">Click here</a>`     
              };
              
              transporter.sendMail(mailOptions, function(error, info){
                res.render("login", {alert: ["Check your email to verify your email before logging in!"]});
              });
        });
    }
    }); 
   
}
});    
    
app.post("/login", demo, isVerified, passport.authenticate("local", {
    successRedirect: "/bank",
    failureRedirect: "/login"
}), function(req, res){

});


app.post("/will", demo2, function(req, res) {

    const will = req.body.myWill;
    const user = req.user.username;

    if (req.body.savebtn === "save") {
        Will.findOne({user: user}, function(err, user){
            user.will.push(will);
            user.draft = "";
            user.save();
            res.redirect("/bank");
        });
    } else if (req.body.draftbtn === "draft") {
        Will.findOne({user: user}, function(err, user){
            user.draft = will;
            user.save();
            res.redirect("/bank");
        });
    }
});

app.post("/delete", demo2, function(req, res){
   Will.findOneAndRemove({user: req.user.username}, function(err){
    const will = new Will({
        user: req.user.username,
        name: req.user.name
    });
            will.save();
            res.redirect("/bank");
   });
  
});

app.post("/passwordchange", demo2, check("newpass", "Password must be at least 8 characters").isLength({min:8}), function(req, res){

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
app.post("/passwordset", demo5, function(req, res){
    
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
                from: process.env.email,
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
app.post("/newpass/:token/:username", demo2, check("password", "Password needs to be at least 8 characters").isLength({min:8}), function(req, res){

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
app.post("/remove", demo2, function(req, res){

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
function isVerified (req, res, next) {
    User.findByUsername(req.body.username, function(err, user){
            if (user) {
                if (user.isVerified === true) {
                    next();
                    return;
                } else {
                    res.render("login", {
                        alert: ["Please verify your email by using the link sent to your email account before logging in"]
                    });
                    return;
                }
            } else {
                res.render("login", {
                    alert: ["Not a Valid User!  Please signup or enter a valid user account login"]
                });
            }
    });
}
function demo(req,res,next) {
    if (req.body.username === "demo"){
        res.render("bank", {alert: ["Normally you would be required to verify an email beofre logging in"], user: "demo", Willlist: ["demo will"], draft: "Welcome to the Demo Bank of Wills!"});
        return;
    } else {
        next();
    }
}
function demo2(req, res, next) {
    if (!req.user) {
        res.render("bank", {alert: ["It worked! Sorry you are only a demo so no data allowed"], user: "demo", Willlist: ["demo will"], draft: "Welcome to the Demo Bank of Wills!"});
        return;
    } else {
        next();
    }
}
function demo3 (req, res, next) {
    if (!req.user) {
        res.render("remove");
        return;
    } else {
        next();
    }
}
function demo4 (req, res, next) {
    if (!req.user) {
        res.render("changepassword");
        return;
    } else {
        next();
    }
}
function demo5 (req, res, next) {
    
    User.findByUsername(req.body.setpassemail, function(err, user){
        if (user) {
            next();
            return;
        } else if (!user) {
            res.render("bank", {alert: ["It worked! Sorry you are only a demo so no data allowed"], user: "demo", Willlist: ["demo will"], draft: "Welcome to the Demo Bank of Wills!"});
        }
    });
   
}

// Server ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
app.listen(3000, function(req, res) {
    console.log("Welcome to the Bank of Wills!");
});

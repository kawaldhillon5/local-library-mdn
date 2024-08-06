const express = require("express");
const router = express.Router();
const asyncHandler = require("express-async-handler");
const User = require("../models/user");
const { body, validationResult } = require("express-validator");
const validatePassword = require("./lib/passwordUtils").validatePassword;
const passport = require("passport");
const LocalStrategy = require('passport-local');
const genPassword = require("../routes/lib/passwordUtils").genPassword;

passport.use(
    new LocalStrategy(async (user_name, user_password, done) => {
      try {
        const user =  await User.findOne({userName: user_name}).collation({ locale: "en", strength: 2 }).exec();
        if (!user) {
          return done(null, false, { message: "Incorrect username" });
        };
        const isValid = validatePassword(user_password, user.hash ,user.salt);
        if (isValid) {
            return done(null, user);
        } else {
            return done(null, false, { message: "Incorrect password" });
        }
        
      } catch(err) {
        return done(err);
      };
    })
  );
  
  passport.serializeUser((user, done) => {
    console.log(user);
    done(null, user._id);
  });
  
  passport.deserializeUser(async (_id, done) => {
    try {
      const user = await User.findById(_id).collation({ locale: "en", strength: 2 }).exec();
  
      done(null, user);
    } catch(err) {
      done(err);
    };
  });

  function isAdmin(req, res, next){
    if(req.user.isAdmin){
        next();
    } else {
      res.status(401).json({msg:"You do not have access to this option"});
    }
  }

router.get('/signup',  function(req, res, next) {
    res.render("signup_form",{title: "Create user", errors: []});
});


router.post('/signup', [

    body("user_name")
    .trim()
    .isLength({ min: 1 })
    .escape()
    .withMessage("User name must be specified.")
    .isAlphanumeric()
    .withMessage("User name has non-alphanumeric characters."),
    body("user_email")
    .trim()
    .isLength({ min: 1 })
    .escape()
    .withMessage("Email must be specified."),
    body("user_password")
    .trim()
    .isLength({min: 8})
    .withMessage("Password must at least 8 letters")
    .escape(),
    
    asyncHandler( async (req, res, next) =>{
        
        const errors = validationResult(req);
        const isChecked = (req.body.isAdmin == "on") ? true : false;
        const {salt, hash} = genPassword(req.body.user_password);
        const user = new User({
            userName: req.body.user_name,
            userEmail: req.body.user_email,
            isAdmin: isChecked,
            salt: salt,
            hash: hash,
        });

        if (!errors.isEmpty()) {
            // There are errors. Render form again with sanitized values/errors messages.
            res.render("signup_form", {
              title: "Create User",
              user: user,
              errors: errors.array(),
            });
            return;
        } else {

            const userNameExists = await User.findOne({userName: req.body.user_name}).collation({ locale: "en", strength: 2 }).exec();
            const userEmailExists = await User.findOne({userEmail: req.body.user_email}).collation({ locale: "en", strength: 2 }).exec();
            if(userNameExists){
                res.render('signup_form', {
                    title: "Create User",
                    user: user,
                    errors: [{msg:"User Name already Exists!"}],
                });
            } else if(userEmailExists){
                res.render('signup_form', {
                    title: "Create User",
                    user: user,
                    errors: [{msg:"Email already Exists!"}],
                });
            } else {
                await user.save();
                res.redirect("/authenticate/login");
            }
            
        } 
    })
]
);


router.get('/login', function(req,res,next) {
    res.render("login_form",{title: "log In",errors:[],userName: req.body.user_name,userPassword: req.body.user_password,});
});

router.post('/login',[
    body("username")
    .trim()
    .isLength({ min: 1 })
    .escape()
    .withMessage("User name must be specified.")
    .isAlphanumeric()
    .withMessage("User name has non-alphanumeric characters."),
    body("password")
    .trim()
    .isLength({min: 1})
    .withMessage("Password must be specified")
    .escape(),

    asyncHandler( async(req, res, next) =>{

        const errors = validationResult(req);

        if (!errors.isEmpty()) {
            // There are errors. Render form again with sanitized values/errors messages.
            res.render("login_form", {
              title: "Log In",
              userName: req.body.username,
              userPassword: req.body.password,
              errors: errors.array(),
            });
            return;
        }
        next();
    }),
    passport.authenticate("local", {
        successRedirect: '/',
        failureRedirect: "/authenticate/login",
        failureMessage: true,
    }),
]);

router.get('/logout', function(req, res, next) {
    req.logout((err) => {
        if (err) {
          return next(err);
        }
        res.redirect("/");
      });
});

module.exports = router;


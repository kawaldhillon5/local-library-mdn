var createError = require('http-errors');
var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var logger = require('morgan');
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
var indexRouter = require('./routes/index');
const catalogRouter = require("./routes/catalog"); //Import routes for "catalog" area of site
const authRouter = require('./routes/authenticate');
var app = express();

const MongoStore = require('connect-mongo');

mongoose.set("strictQuery", false);
const mongoDB = "mongodb+srv://dhillonzeus:nlnU6050@cluster0.dvd8zsi.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0";


main().catch((err) => console.log(err));
async function main() {
  await mongoose.connect(mongoDB);
}


// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'jade');

app.use(session({ 
  secret: "cats", 
  resave: false, 
  saveUninitialized: false,
  store: MongoStore.create(
    {mongoUrl:mongoDB}
    ),
  cookie: { maxAge: 1000 * 60 * 60 * 24 }, 
}));

app.use(passport.initialize());
app.use(passport.session());

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

app.use("/", indexRouter);
app.use("/catalog", catalogRouter);
app.use("/authenticate", authRouter);


// catch 404 and forward to error handler
app.use(function(req, res, next) {
  next(createError(404));
});

// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('error');
});

module.exports = app;

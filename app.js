var createError = require('http-errors');
var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var logger = require('morgan');
var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;
var FacebookStrategy = require('passport-facebook').Strategy;
const AccountModel = require('./models/account');
const jwt = require('jsonwebtoken');

var indexRouter = require('./routes/index');
var usersRouter = require('./routes/users');

var app = express();

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

app.get('/login', (req, res, next) => {
  res.render('index')
});

app.use(require('express-session')({
  secret: 'keyboard cat',
  resave: true,
  saveUninitialized: true
}));

app.use(passport.initialize());
app.use(passport.session());

// used to serialize the user for the session
passport.serializeUser(function (user, done) {
  done(null, user);
});

// used to deserialize the user
passport.deserializeUser(function (user, done) {
  done(null, user);
});

// Apply passportjs local
passport.use(new LocalStrategy(
  function (username, password, done) {
    AccountModel.findOne({
      username: username,
      password: password
    })
      .then(data => {
        if (!data) done(null, false)
        done(null, data)
      })
      .catch(err => {
        done(err);
      })
  }
));

// Apply passportjs Facebook
passport.use(new FacebookStrategy({
  // Setting FB APP ID & FB APP SECRET HERE
  clientID: '1436352583231532', //FACEBOOK_APP_ID
  clientSecret: `91fa254d1e52d5474ba0a16c91cec637`, //FACEBOOK_APP_SECRET
  callbackURL: "https://ced5d3307e39.ngrok.io/auth/facebook/callback"
},
  function (accessToken, refreshToken, profile, cb) {
    console.log(profile);
    cb(null, profile._json);
  }
));

app.get('/auth/facebook',
  passport.authenticate('facebook'));

app.get('/auth/facebook/callback',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  function (req, res) {
    // Successful authentication, redirect home.
    console.log(req.user);
    res.redirect('/');
  });

app.post('/login', function (req, res, next) {
  passport.authenticate('local', function (err, user) {
    if (err) { return res.status(500).json('Server error') }
    if (!user) { return res.status(500).json("Wrong account"); }

    if (user) {
      jwt.sign(user.toObject(), 'secret_password_here', function (err, token) {
        if (err)
          return res.status(500).json('Server error');

        return res.json(token);
      });
    }
  })(req, res, next);
});

app.get('/private', (req, res, next) => {
  var token = req.headers['authorization'].split(' ')[1];
  jwt.verify(token, 'secret_password_here', function (err, data) {
    if (err) res.status(500).json('Invalid token');
    next();
  })
}, (req, res, next) => {
  res.json('Secret data here');
});

app.use('/', indexRouter);
app.use('/users', usersRouter);

// catch 404 and forward to error handler
app.use(function (req, res, next) {
  next(createError(404));
});

// error handler
app.use(function (err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('error');
});

module.exports = app;

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const session = require('express-session');
const flash = require('connect-flash');
const bodyParser = require('body-parser');
const User = require('./models');
const path = require('path');


const app = express();
const config = require('./config');

mongoose.connect(config.databaseURL);

mongoose.connection.on('error', console.error.bind(console, 'MongoDB connection error:'));

app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({ secret: config.secretKey, resave: false, saveUninitialized: false }));
app.use(flash());

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'DK'));

// Authentication Middleware
function authenticateUser(req, res, next) {
  if (!req.session.user) {
    req.flash('error', 'You must be logged in to access this page.');
    res.redirect('/login');
  } else {
    next();
  }
}

app.get('/register', (req, res) => {
  res.render('register');
});

app.post('/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, email, password: hashedPassword });
    await newUser.save();

    req.flash('success', 'Your account has been created!');
    res.redirect('/login');
  } catch (error) {
    req.flash('error', 'Registration unsuccessful. Please try again.');
    res.redirect('/register');
  }
});

app.get('/login', (req, res) => {
  res.render('login', { messages:{} });
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });

  if (user) {
    if (await bcrypt.compare(password, user.password)) {
      req.session.user = user;
      req.flash('success', 'Login successful!');
      res.redirect('/profile');
    } else {
      req.flash('error', 'Incorrect password. Please try again.');
      res.render('login', { messages: req.flash() });
    }
  } else {
    req.flash('info', 'No account found. Please register.');
    res.render('login', { messages: req.flash() });
  }
});

app.get('/profile', authenticateUser, (req, res) => {
  const username = req.session.user ? req.session.user.username : 'Guest';
  res.render('profile', { username });
});

app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/login');
});

app.listen(24, () => {
  console.log('Server is running on port 24');
});
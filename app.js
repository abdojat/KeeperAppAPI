require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const https = require('https');
const fs = require('fs');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const cors = require('cors');
const _ = require('lodash');
const { ListCollectionsCursor } = require('mongodb');
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const findOrCreate = require('mongoose-findorcreate');

const uri = "mongodb+srv://" + process.env.USER_NAME + ":" + process.env.PASSWORD + "@cluster0.w4z0kmh.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0";

mongoose.connect(uri);

const JWT_SECRET = process.env.secret;

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(session({
    secret: JWT_SECRET,
    resave: false,
    saveUninitialized: true,
}));

app.use(cors({
    origin: 'https://keeperapp-o7lz.onrender.com/',
    credentials: true
}));

app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept');
    next();
});

app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => {
    done(null, user);
});

passport.deserializeUser((user, done) => {
    done(null, user);
});


const noteSchema = new mongoose.Schema({
    title: String,
    content: String
});

const userSchema = new mongoose.Schema({
    username: String,
    password: String,
    email: String,
    googleId: String,
    notes: [noteSchema],
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const Note = mongoose.model('Note', noteSchema);
const User = mongoose.model('User', userSchema);


passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "/auth/google/callback"
},
    function (accessToken, refreshToken, profile, cb) {
        User.findOrCreate({ googleId: profile.id, username: profile.displayName }, function (err, user) {
            return cb(err, user);
        });
    }));


// Routes for Google authentication
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback',
    passport.authenticate('google', { failureRedirect: "https://keeperapp-o7lz.onrender.com/" }),
    function (req, res) {
        const token = jwt.sign({ _id: req.user._id, username: req.user.username }, JWT_SECRET, {
            expiresIn: '10y',
        });
        // Send JWT token in response after successful login
        res.cookie('token', token, { httpOnly: false, secure: false });
        res.redirect('https://keeperapp-o7lz.onrender.com/');
    });

app.post('/register', (req, res) => {
    const { username, password, email } = req.body;
    User.findOne({ username }).exec().then((result) => {
        if (result === null) {
            bcrypt.hash(password, 10).then((result) => {
                const newUser = new User({
                    username: username,
                    password: result,
                    email: email,
                });
                newUser.save();
                const token = jwt.sign({ _id: newUser._id, username: newUser.username }, JWT_SECRET, {
                    expiresIn: '10y',
                });
                res.cookie('token', token, { httpOnly: false, secure: false });
                res.status(201).json({ message: 'User registered successfully', token });
            })
        } else {
            return res.status(400).json({ message: 'User already exists' });
        }
    }).catch(err => res.status(500).json({ message: 'Error during registration', error: err }));
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    User.findOne({ username }).exec().then((result) => {
        if (result === null) {
            return res.status(404).json({ message: 'User not found' });
        }
        else {
            bcrypt.compare(password, result.password).then((isMatch) => {
                if (isMatch) {
                    const token = jwt.sign({ _id: result._id, username: result.username }, JWT_SECRET, {
                        expiresIn: '10y',
                    });
                    res.status(200).json({ message: 'Login successful', token });
                } else {
                    return res.status(401).json({ message: 'Invalid credentials' });
                }
            }).catch((err) => {
                res.status(500).json({ message: 'Error during authentication', error: err });
            });
        }
    });
});

function authenticateToken(req, res, next) {
    const token = req.header('Authorization')?.split(' ')[1];
    if (!token) {
        return res.status(401).json({ message: 'Access denied' });
    }
    try {
        const verified = jwt.verify(token, JWT_SECRET);
        req.user = verified;
        next();
    } catch (err) {
        res.status(400).json({ message: 'Invalid token' });
    }
}


app.get("/protected", authenticateToken, (req, res) => {
    User.findOne({ _id: req.user._id }).exec().then((result) => {
        res.status(200).json(result.notes);
    }).catch((err) => { res.status(500).json({ message: 'Error retrieving data', error: err }); });
});

app.post("/addNote", authenticateToken, (req, res) => {
    const newNote = new Note({
        title: req.body.title,
        content: req.body.content
    });
    User.findOneAndUpdate({ _id: req.user._id }, { $push: { notes: newNote } }, { new: true }).exec().then((result) => {
        res.status(200).json({ message: 'Note added successfully' });
    }).catch((err) => { res.status(500).json({ message: 'Error adding note', error: err }); });
});

app.post("/deleteNote", authenticateToken, (req, res) => {
    User.findOneAndUpdate({ _id: req.user._id }, { $pull: { notes: { _id: req.body.noteId } } }, { new: true }).exec().then((result) => {
        res.status(200).json({ message: 'Note deleted successfully' });
    }).catch((err) => { res.status(500).json({ message: 'Error deleting note', error: err }); });
});

app.listen(3001, () => {
    console.log('listening on https://localhost:3001');
});
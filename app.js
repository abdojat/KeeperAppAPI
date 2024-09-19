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
const findOrCreate = require('mongoose-findorcreate');

const uri = "mongodb+srv://" + process.env.USER_NAME + ":" + process.env.PASSWORD + "@cluster0.w4z0kmh.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0";

mongoose.connect(uri);

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cors());
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept');
    next();
});

const JWT_SECRET = process.env.secret;

const noteSchema = new mongoose.Schema({
    title: String,
    content: String
});

const userSchema = new mongoose.Schema({
    username: String,
    password: String,
    notes: [noteSchema],
});

userSchema.plugin(passportLocalMongoose);

const Note = mongoose.model('Note', noteSchema);
const User = mongoose.model('User', userSchema);

passport.use(User.createStrategy());

passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

app.post('/register', (req, res) => {
    const { username, password } = req.body;
    User.findOne({ username }).exec().then((result) => {
        if (result === null) {
            bcrypt.hash(password, 10).then((result) => {
                const newUser = new User({
                    username: username,
                    password: result,
                });
                console.log(newUser);
                newUser.save();
                res.status(201).send('User registered successfully');
            })
        } else {
            res.status(400).send('User already exists')
        }
    }).catch(err => res.send(err));
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    console.log(req.body);
    User.findOne({ username }).exec().then((result) => {
        if (result === null) {
            return res.status(404).json({ message: 'User not found' });
        }
        else {
            bcrypt.compare(password, result.password).then((isMatch) => {
                if (isMatch) {
                    const token = jwt.sign({ _id: result._id }, JWT_SECRET, {
                        expiresIn: '1h',
                    });
                    console.log(token);
                    res.json({ message: 'Login successful', token });
                } else {
                    return res.status(401).json({ message: 'Invalid credentials' });
                }
            }).catch((err) => {
                res.send(err);
            });
        }
    });
});

function authenticateToken(req, res, next) {
    console.log(req.body);
    const token = req.header('Authorization')?.split(' ')[1];
    if (!token) {
        return res.status(401).send('Access denied');
    }
    try {
        const verified = jwt.verify(token, JWT_SECRET);
        req.user = verified;
        next();
    } catch (err) {
        res.status(400).send('Invalid token');
    }
}


app.get("/protected", authenticateToken, (req, res) => {
    User.findOne({ _id: req.user._id }).exec().then((result) => {
        res.send(result.notes);
    }).catch((err) => { res.send(err); });
});

app.post("/addNote", authenticateToken, (req, res) => {
    const newNote = new Note({
        title: req.body.title,
        content: req.body.content
    });
    User.findOneAndUpdate({ _id: req.user._id }, { $push: { notes: newNote } }, { new: true }).exec().then((result) => {
        res.send("ok");
    }).catch((err) => { res.send(err); });
});

app.post("/deleteNote", authenticateToken, (req, res) => {
    User.findOneAndUpdate({ _id: req.user._id }, { $pull: { notes: { _id: req.body.noteId } } }, { new: true }).exec().then((result) => {
        res.send("ok");
    }).catch((err) => { res.send(err); });
});

app.listen(3001, () => {
    console.log('HTTPS Server running on https://localhost:3001');
});
const express = require('express');
const User = require('../models/User.model');
const router = express.Router();
const saltRound = 10;
const bcrypt = require('bcrypt');

router.get('/signup', (req, res, next) => {
	res.render('signup');
});

router.get('/login', (req, res, next) => {
	res.render('login');
});

router.get('/profile', (req, res) => {
	res.render('profile');
});

module.exports = router;

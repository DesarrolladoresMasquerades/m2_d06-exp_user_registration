require('dotenv/config');

require('./db');

const express = require('express');

const hbs = require('hbs');

const app = express();

require('./config')(app);

const projectName = 'lab-express-basic-auth';
const capitalized = string => string[0].toUpperCase() + string.slice(1).toLowerCase();

app.locals.title = `${capitalized(projectName)}- Generated with Ironlauncher`;

const index = require('./routes/index');
const authRouter = require('./routes/auth.routes');

app.use('/', index);
app.use('/auth', authRouter);

// ❗ To handle errors. Routes that don't exist or errors that you handle in specific routes
require('./error-handling')(app);

module.exports = app;


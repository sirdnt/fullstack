const express = require('express');
const bodyParser = require('body-parser');
const morgan = require('morgan');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const jwtPrivateKey = "jwt-private-key";
//for md5 password
const salt = 'd2g6IOP(U(&Â§)%UÂ§VUIPU(HN%V/Â§Â§URerjh0Ã¼rfqw4zoÃ¶qe54gÃŸ0Ã¤Q"LOU$3wer'

const app = express();
app.use(morgan('dev'));
app.use(bodyParser.json());

var users = new Array(); //mock database save user

app.get('/api', (req, res) => {
    res.json({
        message: 'welcome to test jwt api'
    });
});

function verifyEmailPassword(req, res, next) {
    console.log(req.body);
    const email = req.body.email;
    const password = req.body.password;
    if (email !== undefined && password !== undefined) {
        next()
    } else {
        res.json({
            message: "missing infomation"
        });
    }
}

function hashPassword(req, res, next) {
    const password = req.body.password;
    const passwordMD5 = crypto.createHash('md5').update(salt + password).digest('hex');
    req.body.hashPassword = passwordMD5;
    next();
}

function findOne(email) {
    var findUsers = users.filter((indexUser) => {
        return indexUser.email === email
    });
    if (findUsers.length > 0) {
        return findUsers[0];
    } else {
        return undefined;
    }
}

function findAuth(email, password) {
    var findUsers = users.filter((indexUser) => {
        return indexUser.email === email && indexUser.password == password
    });
    if (findUsers.length > 0) {
        return findUsers[0];
    } else {
        return undefined;
    }
}

app.post('/api/register', verifyEmailPassword, hashPassword, (req, res) => {
    var checkUser = findOne(req.body.email);
    console.log("check user: " + checkUser);
    if (checkUser) {
        res.json({
            message: "email has been used"
        });
        return;
    }
    const newUser = {
        email: req.body.email,
        password: req.body.hashPassword
    };
    users.push(newUser);
    res.json({
        message: 'register success',
        user: newUser
    });
});

app.post('/api/login', verifyEmailPassword, hashPassword, (req, res) => {
    var authUser = findAuth(req.body.email, req.body.hashPassword);
    if (authUser) {
        jwt.sign(authUser, jwtPrivateKey, (err, token) => {
            if (err) {
                res.json({
                    message: "login error",
                    err
                });
            } else {
                res.json({
                    message: "login success",
                    token
                });
            }
        });
    } else {
        res.sendStatus(404);
    }
});

app.post('/api/profile', (req, res) => {
    //get token from header request
    const token = req.headers['authorization'];
    //check if token exist
    if (token) {
        // decode token
        jwt.verify(token, jwtPrivateKey, (err, decodedData) => {
            // console.log("jwt verify with err : " + err + " ... data: " + decodedData);
            if (err) {
                res.status = 401;
                res.json({
                    message: "unothorized",
                    err
                });
            } else {
                var checkUser = findAuth(decodedData.email, decodedData.password);
                if (checkUser) {
                    res.json({
                        message: "success",
                        checkUser
                    });
                } else {
                    res.sendStatus(404);
                }
            }
        });
    } else {
        //if not send status unauthorize
        res.sendStatus(403);
    }
});

app.listen(3000, () => {
    console.log('App listening on port 3000!');
});
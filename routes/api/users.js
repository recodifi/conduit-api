const mongoose = require('mongoose');
const router = require('express').Router();
const passport = require('passport');
const User = mongoose.model('User');
const auth = require('../auth');

// register new user
router.post('/users', function (req, res, next) {
  let user = new User();

  user.username = req.body.user.username;
  user.email = req.body.user.email;
  user.setPassword(req.body.user.password);

  user.save()
      .then(function () {
        return res.json({user: user.toAuthJSON()});
      })
      .catch(next);
});

// login registered user
router.post('/users/login', function (req, res, next) {
  if (!req.body.user.email) {
    return res.status(422).json({errors: {email: 'can not be blank'}});
  }
  if (!req.body.user.password) {
    return res.status(422).json({errors: {email: 'can not be blank'}});
  }

  passport.authenticate('local', {session: false}, function (err, user, info) {
    if (err) return next(err);

    if (user) {
      user.token = user.generateJWT();
      return res.json({user: user.toAuthJSON()});
    } else {
      return res.status(422).json(info);
    }
  })(req, res, next);
});

// endpoint to get the current user's auth payload from their token
router.get('/user', auth.required, function (req, res, next) {
  User.findById(req.payload.id)
      .then(function (user) {
        if (!user) return res.sendStatus(401);

        return res.json({user: user.toAuthJSON()});
      })
      .catch(next);
});

// update users endpoint
router.put('/user', auth.required, function (req, res, next) {
  User.findById(req.payload.id)
      .then(function (user) {
        if (!user) return res.sendStatus(401);

        // only update fields that were actually passed
        if (typeof req.body.user.username !== 'undefined') {
          user.username = req.body.user.username;
        }
        if (typeof req.body.user.email !== 'undefined') {
          user.email = req.body.user.email;
        }
        if (typeof req.body.user.bio !== 'undefined') {
          user.bio = req.body.user.bio;
        }
        if (typeof req.body.user.password !== 'undefined') {
          user.setPassword(req.body.user.password);
        }
        if(typeof req.body.user.image !== 'undefined') {
          user.image = req.body.user.image;
        }

        return user.save().then(function () {
          return res.json({user: user.toAuthJSON()});
        });
      })
      .catch(next);
});

module.exports = router;
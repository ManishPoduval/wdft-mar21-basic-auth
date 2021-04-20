const router = require("express").Router();
const bcrypt = require('bcryptjs');
const UserModel = require('../models/User.model')

let userInfo = {}

// GET route to show the user the sign-in form
router.get('/signin', (req, res) => {
    res.render('auth/signin.hbs')
})

// GET route to show the user the sign-up form
router.get('/signup', (req, res) => {
  res.render('auth/signup.hbs')
})


router.post('/signup', (req, res, next)=> {
    const {username, email, password} = req.body

    //Validate all the inputs

    // Check if the inputs do not exist
    if (!username || !email || !password ) {
        res.render('auth/signup.hbs', {msg: 'Please enter all fields'})
        // tell node to come out of the callback code
        return;
    }

    //Validate Password: 
    const passRe = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{8,}$/
    if (!passRe.test(password)) {
      res.render('auth/signup.hbs', {msg: 'Password must be 8 characters, must have a number, and an uppercase Letter'})
      // tell node to come out of the callback code
      return;
    }

    // Validate an email: it should have an @ and . symbol in it
    // use a regEx
    const re = /^[^@ ]+@[^@ ]+\.[^@ ]+$/;
    if (!re.test(String(email).toLowerCase())) {
      res.render('auth/signup.hbs', {msg: 'Please enter a valid email format'})
      // tell node to come out of the callback code
      return;
    }

    const salt = bcrypt.genSaltSync(12);
    const hash = bcrypt.hashSync(password, salt);

    UserModel.create({username, email, password: hash })
      .then(() => {
        res.redirect('/')

        // ----------------------------------------------
        // The code below is just to show how error handling works
        // We wont throw anything in the then block without conditionals
        /*
          if (!manish){
              throw 'Please refresh the page'
          }
          */
      })
      .catch((err) => {

        // Calls the next available function/middleware
        // next()

          // when you pass a parameter it calls the error handling middleware specifically
          next('Beautiful error message') // looks error handling middleware
      })
})

router.post('/signin', (req, res, next) => {
    const {email, password} = req.body

  // You can do the same validations as you didin signup for email and password
  
  //1. find the user with the email

  // 2. compare the password with bcrypt

  UserModel.findOne({email})
    .then((response) => {
        // when email does not exists, response will be an null
        if(!response) {
          res.render('auth/signin.hbs', {msg: 'Email or password seems to be incorrect'})
        }
        else {
              // 2. compare the password with bcrypt
              // response.password is the hashed password from the db
              // password is the one that the user typed in the input, we use from req.body
              bcrypt.compare(password, response.password)
                .then((isMatching) => {
                  //compare will return a true or a false
                      if (isMatching) {
                        // if the user has signin in successfully redirect to profile
                        // userInfo = response
                        console.log('Session before update ', req.session)
                        req.session.userInfo = response
                        req.app.locals.isUserLoggedIn = true 
                        console.log('Session after update ', req.session)

                        res.redirect(`/profile`)
                      }
                      else {
                        res.render('auth/signin', {msg: 'Email or password seems to be incorrect'})
                      }
                })
        }
    })
    .catch((err) => {
        // it will come here if mongoose crases for some reasons
        next(err)
    })
})

//CUSTOM Middlewares functions

const authorize = (req, res, next) => {
  console.log('See I\'m here')
  if (req.session.userInfo) {
    next()
  }
  else {
    res.redirect('/signin')
  }
  
}

// Creating protected routes
router.get('/profile', authorize, (req, res, next) => {
  console.log('Hey, in profile')  
  const {email} = req.session.userInfo 
   res.render('profile.hbs', {email})
})


router.get('/logout', (req, res, next) => {
    req.app.locals.isUserLoggedIn = false  
    req.session.destroy()
    res.redirect('/')
})

module.exports = router;
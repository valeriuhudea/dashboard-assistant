const { Router } = require('express')
const strategy = require('../strategy')
const protectedRoutes = require('./dashboard')
const unprotectedRoutes = require('./public')
const logoutRoute = require('./logout')

const router = Router()
router.use(strategy.router)
router.use(unprotectedRoutes)

router.use(async function Authenticated(req, res, next) {
  res.locals.authenticated = req.session.passport && req.user
  //console.log(res.locals.authenticated)
  if (res.locals.authenticated) {
    res.locals.accounts = {}

    Object.keys(req.session.accounts).forEach(function(acc) {
      res.locals.accounts[acc] = req.session.accounts[acc].pub
    })
  }
  //res.locals.originalUrl = req.originalUrl
  next()
})

router.use('/dashboard', (req, res, next) => {
  const authenticated = req.isAuthenticated()
  if (authenticated) {
    next()
  } else {
    res.render('unauthorized')
  }
}, protectedRoutes)

router.use('/logout', (req, res, next) => {
  const authenticated = req.isAuthenticated()
  if (authenticated) {
    next()
  } else {
    res.render('unauthorized')
  }
}, logoutRoute)

router.use((error, req, res, next) => {
  const { status = 404, message } = error
  res.render('notfound', { status, message })
})

module.exports = router

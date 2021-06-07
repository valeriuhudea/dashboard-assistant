const { Router } = require('express')
const strategy = require('../strategy')
const dashboardRoutes = require('./dashboard')
const unprotectedRoutes = require('./public')
const logoutRoute = require('./logout')

const router = Router()
router.use(strategy.router)
router.use(unprotectedRoutes)

router.use(async function enforceAuth(req, res, next) {
  if (req.isAuthenticated() && req.session.passport) {
    res.locals.authenticated = req.session.passport
    return next()
  }
  res.redirect('/')
})

router.use('/dashboard', (req, res, next) => {
  next()
}, dashboardRoutes)


router.use('/logout', (req, res, next) => {
  next()
}, logoutRoute)

router.use((error, req, res, next) => {
  const { status = 404, message } = error
  console.log(error)
  res.redirect('/error')
})

module.exports = router

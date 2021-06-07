const { Router } = require('express')
const router = Router()
const strategy = require('../strategy')

router.get('/', async (req, res) => {
  const cookieAccepted = req.cookies.cookieAccepted ? parseInt(req.cookies.cookieAccepted, 10) : null
  res.render('index', { cookieAccepted })
})

router.get('/unauthorized', async (req, res) => {
  res.render('unauthorized')
})

router.get('/error', async (req, res, errorMessage, next) => {
  res.render('error', { errorMessage })
})

module.exports = router

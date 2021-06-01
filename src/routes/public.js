const { Router } = require('express')
const router = Router()
const strategy = require('../strategy')

router.get('/', async (req, res) => {
  res.render('index')
})

module.exports = router

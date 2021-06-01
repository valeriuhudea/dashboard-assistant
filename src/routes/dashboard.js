//require('dotenv').config()
const { Router } = require('express')
const jwtDecode  = require('jwt-decode')
//const querystring = require('querystring')
const axios = require('axios')
const isEmail = require('validator/lib/isEmail')
const { reset } = require('nodemon')
//const { stringify } = require('qs')
const router = Router()

router.get('/', async (req, res) => {
  res.render('dashboard', { csrfToken: req.csrfToken() })
})

router.post('/service/checkup', async (req, res, next) => {
  const user_terminate = req.body.terminate_user
  const validated_email = isEmail(user_terminate)
  const accessing_admin = Object.values(req.session.passport.user)

  const authz = accessing_admin[0].secret.access_token

  if (validated_email  == false) {
    res.redirect('/dashboard')
  } else {
    const whois_user = await axios({
      method: 'GET',
      url: `${process.env.OKTA_DOMAIN}/api/v1/users?filter=profile.login+eq+"${user_terminate}"`,
      headers: {
        'accept': 'application/json',
        'content-type': 'application/json',
        'authorization': `Bearer ${authz}`
      }
    }).catch(error => {
      if ( '403' in error) {
        res.render('forbidden', { errorMessage: error.status })
      } else {
        res.render('unauthorized', { errorMessage: error })
      }
    })
    const user_info = whois_user.data
    const status = whois_user.status

    if (user_info == '' || user_info == undefined) {
      res.render('forbidden', { message: "User was not found or your don't have enough permissions to view account!", status: status })
    } else {
      const userId = user_info[0].id
      const user_status = user_info[0].status
      const lastLogin = user_info[0].lastLogin
      const lastUpdated = user_info[0].lastUpdated
      const passwordChanged = user_info[0].passwordChanged

      const confirmUser = {
        email: user_terminate,
        userId: userId,
        status: user_status,
        lastLogin: lastLogin,
        lastUpdated: lastUpdated,
        passwordChanged: passwordChanged
      }
      res.render('confirmation', {
        id: userId,
        csrfToken: req.csrfToken(),
        btnTitle: 'Confirm',
        action: '/dashboard/service/terminate',
        method: 'POST',
        fields: [
          { name: 'Email', type: 'email', value: confirmUser.email },
          { name: 'Status', type: 'text', value: confirmUser.status },
          { name: 'LastLogin', type: 'text',  value: confirmUser.lastLogin },
          { name: 'LastUpdated', type: 'text', value: confirmUser.lastUpdated },
          { name: 'LasswordChanged', type: 'text', value: confirmUser.passwordChanged }
        ]
      })
    }
  }
})

router.post('/service/terminate', async (req, res, next) => {
  const terminateId = req.body.userid
  const accessing_admin = Object.values(req.session.passport.user)
  const authz = accessing_admin[0].secret.access_token
  try {
    //Password Reset in HUB
    const pw_res_resp = await axios({
      method: 'POST',
      url: `${process.env.OKTA_DOMAIN}/api/v1/users/${terminateId}/lifecycle/reset_password?sendEmail=false`,
      headers: {
        'accept': 'application/json',
        'content-type': 'application/json',
        'authorization': `Bearer ${authz}`
      }
    }).catch(error => {
      res.render('unauthorized', { fullError: error })
    })

    const pw_res_status = pw_res_resp.status
    const pw_res_data = pw_res_resp.data

    //Session Termination Process in HUB
    const ses_call_resp = await axios({
      method: 'DELETE',
      url: `${process.env.OKTA_DOMAIN}/api/v1/users/${terminateId}/sessions?ouathTokens=true`,
      headers: {
        'accept': 'application/json',
        'content-type': 'application/json',
        'authorization': `Bearer ${authz}`
      }
    }).catch(error => {
      res.render('unauthorized', { fullError: error })
    })
    if (ses_call_resp !== undefined) {
      const resp_status = JSON.stringify(ses_call_resp.status)
      if ( resp_status == 204 ) {
        res.render('success', { successMessage: "Password reset and session termination successful! Status: "+resp_status })
      } else {
        res.json({ message: "Something went wrong, bad request or insuficient permissions.", status: resp_status })
      }
    } else {
      res.json({ message: 'Something went wrong, elevated access may be required!' })
    }
  } catch(error) {
    res.render('unauthorized', { fullError: error })
  }
})

module.exports = router

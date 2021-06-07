//require('dotenv').config()
const { Router } = require('express')
const jwtDecode  = require('jwt-decode')
//const querystring = require('querystring')
const axios = require('axios')
const isEmail = require('validator/lib/isEmail')
const password = require('secure-random-password')

const router = Router()

const randomPassword = password.randomPassword({ characters: [{ characters: password.upper, exactly: 1 }, { characters: password.symbols, exactly: 1 }, password.lower ]})

router.get('/', async (req, res) => {
  var dashboard_date = new Date(Date.now()).toUTCString()

  const adminEmail = Object.values(req.session.passport.user)[0].pub.email

  console.log('%s Dashboard Assistant accessed by %s', dashboard_date, adminEmail)

  var loggedin = (req.session.passport.user) ? (true) : false

  res.render('dashboard', { csrfToken: req.csrfToken(), email: adminEmail, loggedIn: loggedin  })
})

router.post('/service/checkup', async (req, res, next) => {
  const user_terminate = req.body.terminate_user
  const validated_email = isEmail(user_terminate)
  const acc_admin = Object.values(req.session.passport.user)
  const adminEmail = Object.values(req.session.passport.user)[0].pub.email

  const oktaAccessToken = acc_admin[0].secret.access_token
  const aadAccessToken = acc_admin[0].secret.aad_access_token

  if (!validated_email) {
    res.redirect('/dashboard')
  } else {
    const whoisOktaUser = await axios({
      method: 'GET',
      url: `${process.env.OKTA_DOMAIN}/api/v1/users?filter=profile.login+eq+"${user_terminate}"`,
      headers: {
        'accept': 'application/json',
        'content-type': 'application/json',
        'authorization': `Bearer ${oktaAccessToken}`
      }
    })

    const whoisAADUser = await axios({
      method: 'GET',
      // eslint-disable-next-line max-len
      url: process.env.GRAPH_ENDPOINT + `v1.0/users?$filter=userPrincipalName+eq+'${user_terminate}'`,
      headers: {
        'content-type': 'application/json',
        'authorization': `Bearer ${aadAccessToken}`
      }
    })

    try {
      const okta_user_info = whoisOktaUser.data
      const okat_user_call_status = whoisOktaUser.status
      const aad_user_info = whoisAADUser.data
      const aad_user_call_status = whoisAADUser.status
      // eslint-disable-next-line max-len
      if (okta_user_info == '' || okta_user_info == undefined && aad_user_info.value.length == 0) {
        var okta_user_not_found = true
        var aad_user_not_found = true
        res.render('forbidden', { message: "User doesn't exist in Okta or Azure AD, please retry with a valid email!"})
      } else if (okta_user_info && aad_user_info.value.length > 0) {
        aad_user_not_found = false
        okta_user_not_found = false

        //Okta User
        const oktaUserId = okta_user_info[0].id
        const oktaUserStatus = okta_user_info[0].status
        const oktaLastLogin = okta_user_info[0].lastLogin
        const oktaLastUpdated = okta_user_info[0].lastUpdated
        const oktaPasswordLastChanged = okta_user_info[0].passwordChanged

        //AAD User
        const aadUserId = aad_user_info.value[0].id
        const aadUserUpn = aad_user_info.value[0].userPrincipalName
        const aadUserDisplay = aad_user_info.value[0].displayName

        //Confirmation object
        const confirmUser = {
          email: user_terminate,
          userId: oktaUserId,
          status: oktaUserStatus,
          lastLogin: oktaLastLogin,
          lastUpdated: oktaLastUpdated,
          passwordChanged: oktaPasswordLastChanged,
          microsoftUserPrincipalName: aadUserUpn,
          microsoftDisplayName: aadUserDisplay,
          aaduserId: aadUserId
        }
        res.render('confirmation', {
          oktaId: oktaUserId,
          aadId: aadUserId,
          csrfToken: req.csrfToken(),
          btnTitle: 'Confirm',
          action: '/dashboard/service/terminate',
          method: 'POST',
          fields: [
            { name: 'Email', type: 'email', value: confirmUser.email },
            { name: 'Status', type: 'text', value: confirmUser.status },
            { name: 'Last Login', type: 'text',  value: confirmUser.lastLogin },
            { name: 'Last Updated', type: 'text', value: confirmUser.lastUpdated },
            { name: 'Last Password Changed', type: 'text', value: confirmUser.passwordChanged },
            { name: 'Microsoft User', type: 'text', value: confirmUser.microsoftUserPrincipalName },
            { name: 'Microsoft Display Name', type: 'text', value: confirmUser.microsoftDisplayName }
          ]
        })
      } else if (okta_user_info && aad_user_info.value.length <= 0) {
        //Okta User
        const oktaUserId = okta_user_info[0].id
        const oktaUserStatus = okta_user_info[0].status
        const oktaLastLogin = okta_user_info[0].lastLogin
        const oktaLastUpdated = okta_user_info[0].lastUpdated
        const oktaPasswordLastChanged = okta_user_info[0].passwordChanged

        const confirmUser = {
          email: user_terminate,
          userId: oktaUserId,
          status: oktaUserStatus,
          lastLogin: oktaLastLogin,
          lastUpdated: oktaLastUpdated,
          passwordChanged: oktaPasswordLastChanged,
          microsoftUserPrincipalName: '',
          microsoftDisplayName: '',
          aaduserId: ''
        }
        res.render('confirmation', {
          oktaId: oktaUserId,
          aadId: '',
          csrfToken: req.csrfToken(),
          btnTitle: 'Confirm',
          action: '/dashboard/service/terminate',
          method: 'POST',
          fields: [
            { name: 'Email', type: 'email', value: confirmUser.email },
            { name: 'Status', type: 'text', value: confirmUser.status },
            { name: 'Last Login', type: 'text',  value: confirmUser.lastLogin },
            { name: 'Last Updated', type: 'text', value: confirmUser.lastUpdated },
            { name: 'Last Password Changed', type: 'text', value: confirmUser.passwordChanged },
            { name: 'Microsoft User', type: 'text', value: 'No Microsoft user' },
            { name: 'Microsoft Display Name', type: 'text', value: 'No Microsoft user' }
          ]
        })
      }
    } catch (error) {
      console.log(error)
    }
  }
})

router.post('/service/terminate', async (req, res, next) => {
  const oktaTerminateId = req.body.okuid
  const aadTerminateId = req.body.aaduid
  const acc_admin = Object.values(req.session.passport.user)
  const oktaAccessToken = acc_admin[0].secret.access_token
  const aadAccessToken = acc_admin[0].secret.aad_access_token
  if (oktaTerminateId != '' && aadTerminateId != '') {
    //Password Reset in HUB
    const ok_pw_res_resp = await axios({
      method: 'POST',
      url: `${process.env.OKTA_DOMAIN}/api/v1/users/${oktaTerminateId}/lifecycle/reset_password?sendEmail=false`,
      headers: {
        'accept': 'application/json',
        'content-type': 'application/json',
        'authorization': `Bearer ${oktaAccessToken}`
      }
    })

    //Session Termination Process in HUB
    const ok_ses_end_resp = await axios({
      method: 'DELETE',
      url: `${process.env.OKTA_DOMAIN}/api/v1/users/${oktaTerminateId}/sessions?ouathTokens=true`,
      headers: {
        'accept': 'application/json',
        'content-type': 'application/json',
        'authorization': `Bearer ${oktaAccessToken}`
      }
    })

    const aadPassResData = JSON.stringify({
      'passwordProfile':
      {
        'forceChangePasswordNextSignIn': false,
        'password': `${randomPassword}`
      },
      'passwordPolicies': 'DisablePasswordExpiration'
    })

    const aad_pw_res_resp = await axios({
      method: 'PATCH',
      url: process.env.GRAPH_ENDPOINT + `v1.0/users/${aadTerminateId}`,
      headers: {
        'content-type': 'application/json',
        'authorization': `Bearer ${aadAccessToken}`
      },
      data: aadPassResData
    }).catch(error => {
      console.log(`Password Reset ${error.message} for: ${aadTerminateId}`)
    })

    const aad_ses_end_resp = await axios({
      method: 'POST',
      // eslint-disable-next-line max-len
      url: process.env.GRAPH_ENDPOINT + `v1.0/users/${aadTerminateId}/revokeSignInSessions`,
      headers: {
        'accept': 'application/json',
        'content-type': 'application/json',
        'authorization': `Bearer ${aadAccessToken}`
      }
    })

    try {
      // eslint-disable-next-line max-len
      if (ok_ses_end_resp !== undefined && ok_pw_res_resp != undefined && aad_ses_end_resp != undefined ) {
        const ok_pw_res_status = ok_pw_res_resp.status
        const ok_ses_end_status = ok_ses_end_resp.status
        //const aad_pw_res_status = aad_pw_res_resp.status
        const aad_ses_end_status = aad_ses_end_resp.status

        const ok_pw_res_data = ok_pw_res_resp.data
        const ok_ses_end_data = ok_ses_end_resp.data
        //const aad_pw_res_data = aad_pw_res_resp.data
        const aad_ses_end_data = aad_ses_end_resp.data
        // eslint-disable-next-line max-len
        console.log('Okta pw res status: '+ok_pw_res_status, 'Okta ses end status: '+ok_ses_end_status,'AAD ses end status: '+aad_ses_end_status)

        res.render('success', { successMessage: 'Session termination successful in Okta and AAD!' })
      }
    } catch(error) {
      res.render('unauthorized', { fullError: error })
    }
  } else if (oktaTerminateId != '' && aadTerminateId == '') {
    const ok_pw_res_resp = await axios({
      method: 'POST',
      url: `${process.env.OKTA_DOMAIN}/api/v1/users/${oktaTerminateId}/lifecycle/reset_password?sendEmail=false`,
      headers: {
        'accept': 'application/json',
        'content-type': 'application/json',
        'authorization': `Bearer ${oktaAccessToken}`
      }
    })

    //Session Termination Process in HUB
    const ok_ses_end_resp = await axios({
      method: 'DELETE',
      url: `${process.env.OKTA_DOMAIN}/api/v1/users/${oktaTerminateId}/sessions?ouathTokens=true`,
      headers: {
        'accept': 'application/json',
        'content-type': 'application/json',
        'authorization': `Bearer ${oktaAccessToken}`
      }
    })

    const ok_pw_res_status = ok_pw_res_resp.status
    const ok_ses_end_status = ok_ses_end_resp.status
    console.log('Okta pw res status: '+ok_pw_res_status, 'Okta ses end status: '+ok_ses_end_status)
    if (ok_pw_res_status == 200 && ok_ses_end_status == 204) {
      res.render('success', { successMessage: 'Session termination successfully in Okta!' })
    } else {
      res.render('error', { errorMessage: 'Something went wrong during Okta API calls!'})
    }
  }
})

module.exports = router

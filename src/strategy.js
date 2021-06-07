const { Router, request } = require('express')
const passport = require('passport')
const jwtDecode  = require('jwt-decode')
const LoginStrategy = require('passport-openidconnect').Strategy
const { now } = require('lodash')
const { uuidv4 } = require('uuid')

const { Strategy } = require('openid-client')

const msal = require('@azure/msal-node')
const axios = require('axios')

const clientConfig = {
  hudea_okta_oauth2: {
    name: process.env.NAME,
    issuer: process.env.OKTA_DOMAIN,
    authorization_endpoint: process.env.AUTHORIZATION_URL,
    token_endpoint: process.env.TOKEN_URL,
    userinfo_endpoint: process.env.USERINFO_URL,
    end_session_endpoint: process.env.ENDSESSION_URL,
    client_id: process.env.CLIENT_ID,
    client_secret: process.env.CLIENT_SECRET,
    scope: process.env.SCOPE
  }
}


const msalConfig = {
  auth: {
    clientId: process.env.AAD_CLIENT_ID,
    authority: process.env.AAD_ENDPOINT + process.env.AAD_TENANT_ID,
    clientSecret: process.env.AAD_CLIENT_SECRET,
    knownAuthorities: []
  },
  cache: {
    // your implementation of caching
  },
  system: {
    loggerOptions: {
      loggerCallback(loglevel, message, containsPii) {
        console.log(message)
      },
      piiLoggingEnabled: false,
      logLevel: msal.LogLevel.Verbose
    }
  }
}

/*
const msalConfig = {
  'authOptions':
  {
    'clientId': process.env.AAD_CLIENT_ID,
    'authority': process.env.AAD_ENDPOINT + process.env.AAD_TENANT_ID,
    'redirectUri': process.env.HOST + '/aad-callback'
  },
  'request':
  {
    'authCodeUrlParameters': {
      'scopes': ["user.read"],
      'redirectUri': process.env.HOST + '/aad-callback'
    },
    'tokenRequest': {
      'code': '',
      'redirectUri': process.env.HOST + '/aad-callback',
      'scopes': ["user.read"]
    },
    'silentRequest': {
      'scopes': ["user.read"]
    }
  },
  'resourceApi':
  {
    'endpoint': process.env.GRAPH_ENDPOINT + '/v1.0/me'
  }
}


const aadGraph = new msal.ConfidentialClientApplication(msalConfig)
*/

const pca = new msal.PublicClientApplication(msalConfig)

const usernamePasswordRequest = {
  scopes: ['Directory.AccessAsUser.All', 'User.ReadWrite.All'],
  username: process.env.AAD_ADMIN,
  password: process.env.AAD_ADMIN_PASS
}

const aadGraphOpt = {
  scopes: [process.env.GRAPH_ENDPOINT + '.default',],
  skipCache: true
}

let activeConfigs = {}
const getStatus = (name) => !!activeConfigs[name]

const router = Router()

router.get('/auth/:name', (req, ...args) => {
  const { name } = req.params
  if (!getStatus(name)) initAuth(name)
  var redirectTo = req.query
  var state = redirectTo ? new Buffer.from(JSON.stringify(redirectTo)).toString('base64') : uuidv4()
  const authenticator = passport.authenticate(name,
    {
      failureRedirect: '/unauthorized',
      state
    }
  )
  return authenticator(req, ...args)
})

router.get('/auth/:name/callback', (req, res, ...args) => {
  const { name } = req.params
  if(req.query && 'error' in req.query) {
    try {
      const oktaError = req.query.error
      const oktaErrorD = req.query.error_description
      const errmsg = `${oktaError} due to ${oktaErrorD}`
      res.render('error', { errorMessage: errmsg })
    } catch (error) {
      console.error(error)
    }
  }
  const authenticator = passport.authenticate(name,
    {
      failureRedirect: '/unauthorized',
      successRedirect: '/dashboard',
      state: req.query.state
    }
  )
  return authenticator(req, res, ...args)
})

// this can be loaded whenever a config is updated
const initAuth = (name) => {

  activeConfigs[name] = true
  const config = clientConfig.hudea_okta_oauth2
  if (config)  {
    const {
      client_id,
      client_secret,
      issuer,
      authorization_endpoint,
      token_endpoint,
      userinfo_endpoint,
      scope
    } = config
    passport.use(
      name,
      new LoginStrategy(
        {
          issuer: issuer,
          authorizationURL: authorization_endpoint,
          clientID: client_id,
          tokenURL: token_endpoint,
          clientSecret: client_secret,
          callbackURL: `${process.env.HOST}/auth/${name}/callback`,
          userInfoURL: userinfo_endpoint,
          scope: scope,
          skipUserProfile: true,
          passReqToCallback: false,
          realm: process.env.HOST
        },
        async (iss, sub, profile, accessToken, refreshToken, tokens, done)  => {
          try {
            //Check id_token and access_token issued from authentication
            const decodedAccessToken = jwtDecode(tokens.access_token)
            const decodedIdToken = jwtDecode(tokens.id_token)

            const aadGraphAuthCall = pca.acquireTokenByUsernamePassword(usernamePasswordRequest)
            const aadGraphAuthCallResp = await aadGraphAuthCall
            console.log(aadGraphAuthCall)

            //const aadGraphCall = aadGraph.acquireTokenByClientCredential(aadGraphOpt)
            //const aadGraphResp = await aadGraphCall
            //console.log(aadGraphResp)
            const aadAccessToken = aadGraphAuthCallResp.accessToken
            //const decodeAadAccessToken = jwtDecode(aadAccessToken)
            //console.log(decodeAadAccessToken)
            //const aad_acs_scope = aadGraphResp.scopes
            // Define User Object Attributes: email, userid, scopes and tokens
            const userEmail = decodedIdToken.email

            const expiry = tokens.expires_in
            const iat = decodedAccessToken.iat
            const exp = decodedAccessToken.exp
            const token_exp = new Date((iat + expiry) * 1000).toLocaleString()

            const userId = decodedAccessToken.uid
            const okta_acs_scope = decodedAccessToken.scp
            

            var activate = true

            const user = {
              [userEmail]: {
                pub: {
                  issuer: issuer,
                  email: userEmail,
                  valid_until: token_exp
                },
                secret: {
                  userId: userId,
                  id_token: tokens.id_token,
                  access_token: accessToken,
                  aad_access_token: aadAccessToken
                }
              }
            }
            var access_date = new Date(Date.now()).toUTCString()
            console.log('%s Logged in with: %s and valid until %s', access_date, userEmail, token_exp)
            return done(null, user)
          } catch (error) {
            console.error(error)
          }
        }
      )
    )
  }
}

module.exports =  {
  router
}

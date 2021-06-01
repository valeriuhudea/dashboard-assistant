const { Router } = require('express')
const passport = require('passport')
const jwtDecode  = require('jwt-decode')
const LoginStrategy = require('passport-openidconnect').Strategy

var clientConfig = {
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

let activeConfigs = {}
const getStatus = (name) => !!activeConfigs[name]


const router = Router()

router.get('/auth/:name', (req, res, next) => {
  const { name } = req.params
  if (!getStatus(name)) initAuth(name)
  var redirectTo = req.query
  var state = redirectTo ? new Buffer.from(JSON.stringify(redirectTo)).toString('base64') : undefined
  const authenticator = passport.authenticate(name,
    {
      failureRedirect: '/',
      state
    }
  )
  authenticator(req, res, next)
})

/*
router.get('/auth/:name/callback', (req, res, next, ...args) => {
  const { name } = req.params
  if (req.query.error) {
    return res.redirect('/')
  } else {
    return passport.authenticate(name, { failureRedirect: '/' }),
    function(req, res) {
      try {
        var state = req.query.state
        req.session.accounts = req.session.accounts || {}
        req.session.accounts[name] = Object.assign({}, req.user)
      } catch (error) {
        console.log(error)
        res.render('unauthorized', { errorMessage: error })
      }
      res.redirect('/dashboard')
    }(req, ...args)
  }
})
*/

const name = process.env.NAME
router.get(`/auth/${name}/callback`, (req, res, next) => {
  if (req.query.error) {
    return res.redirect('/')
  }
  next()
}, passport.authenticate(name, { failureRedirect: '/' }),
function(req, res, next) {
  try {
    var state = req.query.state
    req.session.accounts = req.session.accounts || {}
    req.session.accounts[name] = Object.assign({}, req.user)
  } catch (error) {
    console.log(error)
    res.render('unauthorized', { errorMessage: error })
  }
  res.redirect('/dashboard')
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
        (iss, sub, profile, accessToken, refreshToken, tokens, done)  => {
          try {
            //Check id_token and access_token issued from authentication
            const decodedAccessToken = jwtDecode(tokens.access_token)
            const decodedIdToken = jwtDecode(tokens.id_token)

            // Define User Object Attributes: email, userid, scopes and tokens
            const userEmail = decodedIdToken.email

            const expiry = tokens.expires_in
            const iat = decodedAccessToken.iat
            const exp = decodedAccessToken.exp
            const token_exp = new Date((iat + expiry) * 1000).toLocaleString()

            const userId = decodedAccessToken.uid
            const acs_scope = decodedAccessToken.scp
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
                  scope: acs_scope
                }
              }
            }
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
  router,
  initAuth
}

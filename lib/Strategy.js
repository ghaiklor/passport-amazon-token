var util = require('util');
var OAuth2Strategy = require('passport-oauth').OAuth2Strategy;
var InternalOAuthError = require('passport-oauth').InternalOAuthError;

util.inherits(AmazonTokenStrategy, OAuth2Strategy);

/**
 * `Strategy` constructor.
 * The Amazon authentication strategy authenticates requests by delegating to Amazon using OAuth2 access tokens.
 * Applications must supply a `verify` callback which accepts a accessToken, refreshToken, profile and callback.
 * Callback supplying a `user`, which should be set to `false` if the credentials are not valid.
 * If an exception occurs, `error` should be set.
 *
 * Options:
 * - clientID          Identifies client to Amazon App
 * - clientSecret      Secret used to establish ownership of the consumer key
 * - passReqToCallback If need, pass req to verify callback
 *
 * Example:
 *     passport.use(new AmazonTokenStrategy({
 *           clientID: '123-456-789',
 *           clientSecret: 'shhh-its-a-secret',
 *           passReqToCallback: true
 *       }, function(req, accessToken, refreshToken, profile, next) {
 *              User.findOrCreate(..., function (error, user) {
 *                  next(error, user);
 *              });
 *          }
 *       ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @constructor
 */
function AmazonTokenStrategy(options, verify) {
  options = options || {};
  options.authorizationURL = options.authorizationURL || 'https://www.amazon.com/ap/oa';
  options.tokenURL = options.tokenURL || 'https://api.amazon.com/auth/O2/token';

  OAuth2Strategy.call(this, options, verify);

  this.name = 'amazon-token';
  this._passReqToCallback = options.passReqToCallback;
  this._oauth2._useAuthorizationHeaderForGET = true;
}

/**
 * Authenticate method
 * @param {Object} req
 * @param {Object} options
 * @returns {*}
 */
AmazonTokenStrategy.prototype.authenticate = function (req, options) {
  var self = this;
  var accessToken = (req.body && req.body.access_token) || (req.query && req.query.access_token) || (req.headers && req.headers.access_token);
  var refreshToken = (req.body && req.body.refresh_token) || (req.query && req.query.refresh_token) || (req.headers && req.headers.refresh_token);

  if (!accessToken) {
    return self.fail({message: 'You should provide access_token'});
  }

  self._loadUserProfile(accessToken, function (error, profile) {
    if (error) return self.error(error);

    function verified(error, user, info) {
      if (error) return self.error(error);
      if (!user) return self.fail(info);

      return self.success(user, info);
    }

    if (self._passReqToCallback) {
      self._verify(req, accessToken, refreshToken, profile, verified);
    } else {
      self._verify(accessToken, refreshToken, profile, verified);
    }
  });
};

/**
 * Parse user profile
 * @param {String} accessToken Amazon OAuth2 access token
 * @param {Function} done
 */
AmazonTokenStrategy.prototype.userProfile = function (accessToken, done) {
  this._oauth2.get('https://api.amazon.com/user/profile', accessToken, function (error, body, res) {
    if (error) return done(new InternalOAuthError('Failed to fetch user profile', error));

    try {
      var json = JSON.parse(body);
      var profile = {
        provider: 'amazon',
        id: json.id,
        displayName: json.displayName || '',
        name: {
          familyName: (json.name && json.name.familyName) || '',
          givenName: (json.name && json.name.givenName) || ''
        },
        emails: json.emails || [],
        photos: [{
          value: (json.image && json.image.url) || ''
        }],
        _raw: body,
        _json: json
      };

      return done(null, profile);
    } catch (e) {
      return done(e);
    }
  });
};

module.exports = AmazonTokenStrategy;

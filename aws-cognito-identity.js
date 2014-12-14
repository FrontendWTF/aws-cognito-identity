angular.module('aws.cognito.identity', [
  'aws',
  'google.auth',
  'facebook.auth'
]).provider('CognitoIdentity', function () {
  var options = {
    accountId: null,
    poolId: null,
    anonymousRole: null,
    authenticatedRole: null
  };
  var providers = {};

  var provider = {
    config: function (extra) {
      if (extra) {
        options = angular.extend(options, extra);

        return provider;
      } else {
        return options;
      }
    },
    $get: function (
      $q,
      $injector,
      $window,
      $timeout,
      $rootScope,
      AWS
    ) {
      var deferred = $q.defer();
      var providersReference = 'aws.cognito.identity-providers';

      // AWS credentials
      var arnPrefix = 'arn:aws:iam::' + options.accountId + ':role/';
      var baseCredentials = {
        AccountId: options.accountId,
        IdentityPoolId: options.poolId
      };
      var authenticatedCredentials = angular.extend({
        RoleArn: arnPrefix + options.authenticatedRole
      }, baseCredentials);

      var service = {
        promise: deferred.promise,
        providers: providers,
        isAuthenticated: null,
        authenticate: function authenticateByProvider (providerId) {
          return providers[providerId].authenticate();
        },
        getToken: getToken,
        identify: function identify (providerId) {
          if (
            localStorage.getItem(providersReference) ||
              localStorage.getItem(providersReference + '.' + options.poolId)
          ) {
            service.authenticate(providerId);
          } else if (options.anonymousRole) {
            var anonymousCredentials = angular.extend({
              RoleArn: arnPrefix + options.anonymousRole
            }, baseCredentials);

            AWS.config.credentials =
              new AWS.CognitoIdentityCredentials(anonymousCredentials);

            AWS.config.credentials.get(refreshCredentialsCallback);
          }
        }
      };

      function getToken (providerId, token) {
        var params = authenticatedCredentials;
        params.Logins = {};
        params.Logins[providerId] = token;

        AWS.config.credentials =
          new AWS.CognitoIdentityCredentials(params);

        AWS.config.credentials.refresh(function (error) {
          refreshCredentialsCallback(error, provider);
        });

        return deferred.promise;
      }

      function refreshCredentialsCallback (error, provider) {
        if (error) {
          service.isIdentified = false;
          $rootScope.$broadcast('aws.cognito.identity:identifyError', error);

          deferred.reject(error);
        } else {
          var identityId = AWS.config.credentials.identityId;
          var userArn = AWS.config.credentials.params.RoleArn;
          var isAuthenticated =
                (userArn === arnPrefix + options.authenticatedRole);
          $rootScope.$apply(function () {
            service.isAuthenticated = isAuthenticated;
          });

          var identityData = {
            provider: provider,
            identityId: identityId,
            isAuthenticated: isAuthenticated
          };
          $rootScope.$broadcast('aws.cognito.identity:identifySuccess', identityData);

          deferred.resolve(identityData);
        }

        return deferred.promise;
      }

      return service;
    }
  };

  return provider;
}).factory('CognitoIdentityGoogle', function (
  $timeout,
  GoogleAuth,
  CognitoIdentity
) {
  var providerId = 'accounts.google.com';
  var service = {
    authenticate: function () {
      return GoogleAuth.signIn().then(function (response) {
        $timeout(function () {
          service.authenticate();
        }, parseInt(response.expires_in) * 1000);

        return CognitoIdentity.getToken(providerId, response.id_token);
      });
    }
  };

  CognitoIdentity.providers[providerId] = service;

  return service;
}).factory('CognitoIdentityFacebook', function (
  $timeout,
  FacebookAuth,
  CognitoIdentity
) {
  var providerId = 'graph.facebook.com';
  var service = {
    authenticate: function () {
      return FacebookAuth.login().then(function (response) {
        var res = response.authResponse;
        $timeout(function () {
          service.authenticate();
        }, res.expiresIn * 1000);

        return CognitoIdentity.getToken(providerId, res.accessToken);
      });
    }
  };

  CognitoIdentity.providers[providerId] = service;

  return service;
});

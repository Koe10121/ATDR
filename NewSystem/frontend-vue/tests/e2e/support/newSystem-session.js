function bootstrapAuthenticatedRoute(browser, options) {
  var settings = Object.assign({
    route: '/dashboard',
    token: 'newSystem-e2e-token',
    profile: {
      _id: 'acc-1',
      email: 'newSystem.owner@example.com',
      role: 'owner'
    },
    permissions: {}
  }, options || {});

  return browser.executeAsync(function (bootstrapOptions, done) {
    function resolveApp(requireStoreAndRouter) {
      var root = document.getElementById('app');
      var direct = root && root.__vue__ ? root.__vue__ : null;
      var child = root && root.firstElementChild && root.firstElementChild.__vue__
        ? root.firstElementChild.__vue__
        : null;

      function isMatch(app) {
        if (!app) return false;
        if (requireStoreAndRouter) {
          return !!(app.$store && app.$router);
        }
        return !!(app.$router || app.$store);
      }

      if (isMatch(direct)) return direct;
      if (isMatch(child)) return child;

      var appHost = Array.prototype.find.call(document.querySelectorAll('*'), function (node) {
        return !!(node.__vue__ && isMatch(node.__vue__));
      });

      return appHost && appHost.__vue__ ? appHost.__vue__ : null;
    }

    function waitForApp(timeoutAt) {
      return new Promise(function (resolve, reject) {
        (function poll() {
          var app = resolveApp(true);
          if (app) {
            resolve(app);
            return;
          }
          if (Date.now() >= timeoutAt) {
            reject(new Error('app_not_found'));
            return;
          }
          setTimeout(poll, 50);
        })();
      });
    }

    function waitForRoute(app, expectedPath, timeoutAt) {
      return new Promise(function (resolve, reject) {
        (function poll() {
          var currentPath = app && app.$router && app.$router.currentRoute
            ? String(app.$router.currentRoute.path || '')
            : '';
          if (currentPath === expectedPath) {
            resolve(currentPath);
            return;
          }
          if (Date.now() >= timeoutAt) {
            reject(new Error('route_not_reached:' + currentPath));
            return;
          }
          setTimeout(poll, 50);
        })();
      });
    }

    function installDispatchShim(app, shimState) {
      if (!app || !app.$store) {
        throw new Error('store_not_found');
      }

      app.$store.__newSystemE2EState = Object.assign({}, shimState || {});

      if (app.$store.__newSystemOriginalDispatch) {
        return;
      }

      app.$store.__newSystemOriginalDispatch = app.$store.dispatch.bind(app.$store);
      app.$store.dispatch = function (type, payload) {
        var currentShimState = this.__newSystemE2EState || {};
        if (type === 'auth/bootstrapSession') {
          this.commit('set', ['XAccessToken', currentShimState.token || '']);
          this.commit('auth/authenticated', { isAuthen: true, isOAuth: true });
          this.commit('auth/isSignIn', false);
          this.commit('auth/is2FA', false);
          this.commit('auth/profile', currentShimState.profile || {});
          return Promise.resolve(currentShimState.profile || {});
        }

        if (type === 'security/fetchMyPermissions') {
          this.commit('security/setMyPermissions', {
            matrix: currentShimState.permissions || {},
            assignments: [],
            permissions: []
          });
          return Promise.resolve({
            matrix: currentShimState.permissions || {},
            assignments: [],
            permissions: []
          });
        }

        return this.__newSystemOriginalDispatch(type, payload);
      };
    }

    waitForApp(Date.now() + 10000)
      .then(function (app) {
        var token = String(bootstrapOptions.token || '').trim();
        if (!token) {
          throw new Error('missing_token');
        }

        installDispatchShim(app, {
          token: token,
          profile: bootstrapOptions.profile || {},
          permissions: bootstrapOptions.permissions || {}
        });

        window.localStorage.setItem('x-access-token', token);
        app.$store.commit('set', ['XAccessToken', token]);
        app.$store.commit('auth/authenticated', { isAuthen: true, isOAuth: true });
        app.$store.commit('auth/isSignIn', false);
        app.$store.commit('auth/is2FA', false);
        app.$store.commit('auth/profile', bootstrapOptions.profile || {});
        app.$store.commit('security/setMyPermissions', {
          matrix: bootstrapOptions.permissions || {},
          assignments: [],
          permissions: []
        });

        return Promise.resolve(app.$router.push(bootstrapOptions.route))
          .catch(function (error) {
            if (error && error.name === 'NavigationDuplicated') {
              return;
            }
            throw error;
          })
          .then(function () {
            return waitForRoute(app, bootstrapOptions.route, Date.now() + 5000);
          })
          .then(function () {
            return {
              ok: true,
              path: app.$router && app.$router.currentRoute
                ? String(app.$router.currentRoute.path || '')
                : '',
              isAuthen: !!((app.$store.getters['auth/authenticated'] || {}).isAuthen)
            };
          });
      })
      .then(function (result) {
        done(result);
      })
      .catch(function (error) {
        var app = resolveApp(true);
        done({
          ok: false,
          error: error && error.message ? error.message : String(error || 'unknown_error'),
          path: app && app.$router && app.$router.currentRoute
            ? String(app.$router.currentRoute.path || '')
            : String(window.location.pathname || '')
        });
      });
  }, [settings], function (result) {
    var payload = result && result.value ? result.value : {};
    browser.assert.ok(payload.ok, payload.error || 'authenticated route bootstrap succeeded');
    if (settings.route) {
      browser.assert.equal(payload.path, settings.route);
    }
  });
}

module.exports = {
  bootstrapAuthenticatedRoute: bootstrapAuthenticatedRoute
};

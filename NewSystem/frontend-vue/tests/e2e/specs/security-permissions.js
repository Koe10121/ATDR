const { bootstrapAuthenticatedRoute } = require('../support/newSystem-session')

module.exports = {
  'NewSystem security pages load IAM-backed data and save permission matrix rows': function (browser) {
    const devServer = process.env.VUE_DEV_SERVER_URL

    browser
      .url(`${devServer}pages/login`)
      .waitForElementVisible('body', 5000)
    bootstrapAuthenticatedRoute(browser, {
      route: '/security/permissions/matrix',
      permissions: {
        '/security/permission': { all: true, view: true, edit: true, action: true, delete: true },
        '/security/permissions/menu': { all: true, view: true, edit: true, action: true, delete: true, logs: true },
        '/security/permissions/group': { all: true, view: true, edit: true, action: true, delete: true, logs: true },
        '/security/permissions/matrix': { all: true, view: true, edit: true, action: true, delete: true, logs: true }
      }
    })
    browser
      .waitForElementVisible('.security-page', 20000)
      .executeAsync(function (done) {
        var appHost = Array.prototype.find.call(document.querySelectorAll('*'), function (node) {
          return !!(node.__vue__ && node.__vue__.$store && node.__vue__.$router)
        })
        var app = appHost && appHost.__vue__
        if (!app || !app.$store) {
          done({ error: 'app_not_found' })
          return
        }
        app.$store.dispatch('security/permissionMatrix/explorer').then(function () {
          var types = app.$store.getters['security/permissionMatrix/types'] || []
          var menus = app.$store.getters['security/permissionMatrix/menus'] || []
          var groups = app.$store.getters['security/permissionMatrix/groups'] || []
          var permissions = app.$store.getters['security/permissionMatrix/permissions'] || []
          var targetGroup = groups[0] || null
          var targetMenu = menus.find(function (item) {
            return item && item.path === '/accounts/directory'
          }) || menus[0] || null
          var existing = permissions.find(function (item) {
            return item && item.group && item.group._id === (targetGroup && targetGroup._id) && item.menu && item.menu._id === (targetMenu && targetMenu._id)
          }) || null
          if (!targetGroup || !targetMenu) {
            done({ error: 'permission_row_not_found' })
            return
          }
          var payload = {
            _id: existing && existing._id ? existing._id : null,
            groupId: targetGroup && targetGroup._id,
            menuId: targetMenu && targetMenu._id,
            all: true,
            view: true,
            edit: true,
            delete: true,
            action: true,
            logs: true
          }
          return app.$store.dispatch('security/permissionMatrix/save', payload).then(function (saved) {
            var nextPermissions = app.$store.getters['security/permissionMatrix/permissions'] || []
            var savedPermission = nextPermissions.find(function (item) {
              return item && item.groupId === payload.groupId && item.menuId === payload.menuId
            }) || saved
            done({
              typeCount: types.length,
              menuCount: menus.length,
              groupCount: groups.length,
              targetMenuPath: targetMenu && targetMenu.path,
              permissionId: savedPermission && savedPermission._id,
              all: savedPermission && savedPermission.all,
              view: savedPermission && savedPermission.view,
              action: savedPermission && savedPermission.action
            })
          })
        }).catch(function (error) {
          done({ error: error && error.message ? error.message : 'security_matrix_flow_failed' })
        })
      }, [], function (result) {
        browser.assert.ok(!result.value.error, result.value.error || 'security matrix flow succeeded')
        browser.assert.ok(result.value.typeCount >= 1)
        browser.assert.ok(result.value.menuCount >= 1)
        browser.assert.ok(result.value.groupCount >= 1)
        browser.assert.ok(!!result.value.targetMenuPath)
        browser.assert.ok(!!result.value.permissionId)
        browser.assert.equal(result.value.all, true)
        browser.assert.equal(result.value.view, true)
        browser.assert.equal(result.value.action, true)
      })
      .end()
  },

  'NewSystem security menu page keeps newly-created scoped types and menus visible': function (browser) {
    const devServer = process.env.VUE_DEV_SERVER_URL

    browser
      .url(`${devServer}pages/login`)
      .waitForElementVisible('body', 5000)
    bootstrapAuthenticatedRoute(browser, {
      route: '/security/permissions/menu',
      permissions: {
        '/security/permissions/menu': { all: true, view: true, edit: true, action: true, delete: true, logs: true }
      }
    })
    browser
      .waitForElementVisible('.security-page', 20000)
      .executeAsync(function (done) {
        var appHost = Array.prototype.find.call(document.querySelectorAll('*'), function (node) {
          return !!(node.__vue__ && node.__vue__.$store && node.__vue__.$router)
        })
        var app = appHost && appHost.__vue__
        if (!app || !app.$store) {
          done({ error: 'app_not_found' })
          return
        }
        app.$store.dispatch('security/menu/createType', {
          title: [{ key: 'en', value: 'Custom NewSystem Tools' }],
          description: [{ key: 'en', value: 'Created from NewSystem E2E' }],
          state: true
        }).then(function (type) {
          return app.$store.dispatch('security/menu/createMenu', {
            title: [{ key: 'en', value: 'Custom NewSystem Tool' }],
            description: [{ key: 'en', value: 'Custom menu created from NewSystem' }],
            path: '/custom/newSystem-tool',
            typeId: type && type._id,
            state: true
          })
        }).then(function () {
          return app.$store.dispatch('security/menu/explorer')
        }).then(function () {
          var types = app.$store.getters['security/menu/types'] || []
          var menus = app.$store.getters['security/menu/menus'] || []
          done({
            types: types.map(function (item) { return item && item.name }),
            menus: menus.map(function (item) { return item && item.path })
          })
        }).catch(function (error) {
          done({ error: error && error.message ? error.message : 'security_create_flow_failed' })
        })
      }, [], function (result) {
        browser.assert.ok(!result.value.error, result.value.error || 'security create flow succeeded')
        browser.assert.ok((result.value.types || []).some(function (name) { return name === 'Custom NewSystem Tools' }), 'created type remains visible')
        browser.assert.ok((result.value.menus || []).some(function (path) { return path === '/custom/newSystem-tool' }), 'created menu remains visible')
      })
      .end()
  }
}

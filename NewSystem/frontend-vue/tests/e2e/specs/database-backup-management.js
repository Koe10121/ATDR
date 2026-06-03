const appUrl = String(
  process.env.E2E_APP_URL ||
  process.env.TEST_APP_URL ||
  process.env.VUE_DEV_SERVER_URL ||
  'http://127.0.0.1:8080'
).replace(/\/$/, '')
const { bootstrapAuthenticatedRoute } = require('../support/newSystem-session')

module.exports = {
  'Database Backup page manages auto and manual backup': function (browser) {
    browser
      .resizeWindow(1440, 1200)
      .url(`${appUrl}/pages/login`)
      .waitForElementVisible('body', 5000)
    bootstrapAuthenticatedRoute(browser, {
      route: '/config/database-backup',
      permissions: {
        '/accounts/directory': { all: true, view: true, edit: true, action: true, delete: true },
        '/config/runtime-access': { all: true, view: true, edit: true, action: true, delete: true },
        '/config/database-backup': { all: true, view: true, edit: true, action: true, delete: true }
      }
    })
    browser
      .waitForElementVisible('.database-backup-page', 20000)
      .waitForElementVisible('.c-sidebar-nav a[href="/config/database-backup"]', 10000)
      .waitForElementVisible('.database-backup-card', 10000)
      .waitForElementVisible('.database-backup-card--history tbody tr', 10000)
      .assert.containsText('.database-backup-page', 'Database Backup')
      .assert.containsText('.database-backup-card', 'Backup Settings')
      .executeAsync(function (done) {
        function findComponent(vm, name) {
          if (!vm) return null
          if (vm.$options && vm.$options.name === name) return vm
          var children = vm.$children || []
          for (var i = 0; i < children.length; i += 1) {
            var found = findComponent(children[i], name)
            if (found) return found
          }
          return null
        }

        var page = null
        Array.prototype.some.call(document.querySelectorAll('*'), function (node) {
          page = findComponent(node.__vue__, 'DatabaseBackup')
          return !!page
        })
        if (!page) {
          done({ error: 'database_backup_page_not_found' })
          return
        }

        var initialRunCount = page.runs.length
        var initialRunIds = page.runs.map(function (item) { return item._id }).join(',')
        var afterSaveRunIds = ''
        var afterRunCount = 0
        var afterRunIds = ''
        page.settings.autoEnabled = true
        page.settings.intervalHours = 12
        page.settings.retentionCount = 1
        page.loadCollectionPreview().then(function () {
          return page.saveSettings()
        }).then(function () {
          afterSaveRunIds = page.runs.map(function (item) { return item._id }).join(',')
          return page.runBackup()
        }).then(function () {
          afterRunCount = page.runs.length
          afterRunIds = page.runs.map(function (item) { return item._id }).join(',')
          return page.previewBackup(page.runs[0])
        }).then(function () {
          return page.restoreBackup(page.runs[0])
        }).then(function () {
          done({
            autoEnabled: page.settings.autoEnabled,
            intervalHours: page.settings.intervalHours,
            retentionCount: page.settings.retentionCount,
            previewCount: page.collectionPreview.length,
            previewDocuments: page.previewSummary.documentCount,
            historyPreviewCount: page.historyPreview ? page.historyPreview.collectionCount : 0,
            restoredDocuments: page.restoreSummary ? page.restoreSummary.restoredDocuments : 0,
            initialRunCount: initialRunCount,
            afterRunCount: afterRunCount,
            initialRunIds: initialRunIds,
            afterSaveRunIds: afterSaveRunIds,
            afterRunIds: afterRunIds,
            manualRuns: page.runs.filter(function (item) { return item.mode === 'manual' && item.status === 'completed' }).length,
            saving: page.saving
          })
        }).catch(function (error) {
          done({ error: error && error.message ? error.message : 'database_backup_save_or_run_failed' })
        })
      }, [], function (result) {
        browser.assert.ok(!result.value.error, result.value.error || 'database backup save/run succeeded')
        browser.assert.equal(result.value.autoEnabled, true)
        browser.assert.equal(result.value.intervalHours, 12)
        browser.assert.equal(result.value.retentionCount, 1)
        browser.assert.ok(result.value.previewCount >= 1, `preview collection count is ${result.value.previewCount}`)
        browser.assert.ok(result.value.previewDocuments >= 1, `preview document count is ${result.value.previewDocuments}`)
        browser.assert.ok(result.value.historyPreviewCount >= 1, `history preview collection count is ${result.value.historyPreviewCount}`)
        browser.assert.ok(result.value.restoredDocuments >= 1, `restored document count is ${result.value.restoredDocuments}`)
        browser.assert.equal(result.value.afterSaveRunIds, result.value.initialRunIds)
        browser.assert.equal(result.value.afterRunCount, result.value.initialRunCount + 1)
        browser.assert.ok(result.value.afterRunIds.indexOf(result.value.initialRunIds) !== -1, 'manual backup keeps existing history item')
        browser.assert.ok(result.value.manualRuns >= 1, `manual backup count is ${result.value.manualRuns}`)
        browser.assert.equal(result.value.saving, false)
      })
      .end()
  }
}

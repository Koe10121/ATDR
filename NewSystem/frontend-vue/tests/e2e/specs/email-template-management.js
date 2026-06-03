const appUrl = String(
  process.env.E2E_APP_URL ||
  process.env.TEST_APP_URL ||
  process.env.VUE_DEV_SERVER_URL ||
  'http://127.0.0.1:8080'
).replace(/\/$/, '')
const { bootstrapAuthenticatedRoute } = require('../support/newSystem-session')

module.exports = {
  'Email Template Management action button uses the expected NewSystem style': function (browser) {
    browser
      .resizeWindow(1440, 1200)
      .url(`${appUrl}/pages/login`)
      .waitForElementVisible('body', 5000)
    bootstrapAuthenticatedRoute(browser, {
      route: '/config/email-notifications',
      permissions: {
        '/accounts/directory': { all: true, view: true, edit: true, action: true, delete: true },
        '/config/message-authen': { all: true, view: true, edit: true, action: true, delete: true },
        '/config/email-notifications': { all: true, view: true, edit: true, action: true, delete: true }
      }
    })
    browser
      .waitForElementVisible('.email-notification-page', 20000)
      .waitForElementVisible('.email-config-card', 10000)
      .assert.containsText('.email-config-card', 'Delivery Settings')
      .waitForElementVisible('.setting-table-card', 10000)
      .waitForElementVisible('.setting-table-card tbody tr', 10000)
      .waitForElementVisible('.setting-table-card .setting-action-btn', 10000)
      .assert.not.elementPresent('.setting-table-card .setting-remove-btn')
      .execute(function () {
        return {
          actionCount: document.querySelectorAll('.setting-table-card .setting-action-btn').length,
          removeCount: document.querySelectorAll('.setting-table-card .setting-remove-btn').length,
          rows: Array.prototype.map.call(document.querySelectorAll('.setting-table-card tbody tr'), function (row) {
            return row.textContent.replace(/\s+/g, ' ').trim()
          })
        }
      }, [], function (result) {
        browser.assert.equal(result.value.rows.length, 13)
        browser.assert.ok(result.value.rows.some(function (text) { return text.indexOf('Invite Email') !== -1 }), 'invite row is visible')
        browser.assert.ok(result.value.rows.some(function (text) { return text.indexOf('2FA Email') !== -1 }), '2FA row is visible')
        browser.assert.ok(result.value.rows.some(function (text) { return text.indexOf('All Sessions Cleared Email') !== -1 }), 'sessions cleared row is visible')
        browser.assert.ok(result.value.rows.some(function (text) { return text.indexOf('Trusted Device Email') !== -1 }), 'trusted device row is visible')
        browser.assert.ok(result.value.rows.some(function (text) { return text.indexOf('Session Revoked Email') !== -1 }), 'session revoked row is visible')
        browser.assert.ok(result.value.rows.some(function (text) { return text.indexOf('Trusted Device Revoked Email') !== -1 }), 'trusted device revoked row is visible')
        browser.assert.ok(result.value.rows.some(function (text) { return text.indexOf('Payment created') !== -1 }), 'payment created row is visible')
        browser.assert.ok(result.value.rows.some(function (text) { return text.indexOf('Payment paid') !== -1 }), 'payment paid row is visible')
        browser.assert.ok(result.value.rows.some(function (text) { return text.indexOf('Payment failed') !== -1 }), 'payment failed row is visible')
        browser.assert.ok(result.value.rows.some(function (text) { return text.indexOf('Payment refunded') !== -1 }), 'payment refunded row is visible')
        browser.assert.ok(result.value.rows.some(function (text) { return text.indexOf('Merchant approved') !== -1 }), 'merchant approved row is visible')
        browser.assert.ok(result.value.rows.some(function (text) { return text.indexOf('Merchant rejected') !== -1 }), 'merchant rejected row is visible')
        browser.assert.ok(result.value.rows.some(function (text) { return text.indexOf('Settlement completed') !== -1 }), 'settlement completed row is visible')
        browser.assert.ok(!result.value.rows.some(function (text) { return text.indexOf('Account Locked Email') !== -1 }), 'IAM-only locked row is hidden')
        browser.assert.ok(result.value.actionCount >= 13, `action count is ${result.value.actionCount}`)
        browser.assert.equal(result.value.removeCount, 0)
      })
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
          page = findComponent(node.__vue__, 'EmailNotifications')
          return !!page
        })
        if (!page) {
          done({ error: 'email_notification_page_not_found' })
          return
        }
        page.deliveryForm.replyTo = 'ops@newSystem.example.com'
        page.saveDelivery().then(function () {
          done({
            replyTo: page.deliveryForm.replyTo,
            savingDelivery: page.savingDelivery
          })
        }).catch(function (error) {
          done({ error: error && error.message ? error.message : 'email_delivery_save_failed' })
        })
      }, [], function (result) {
        browser.assert.ok(!result.value.error, result.value.error || 'email delivery save succeeded')
        browser.assert.equal(result.value.replyTo, 'ops@newSystem.example.com')
        browser.assert.equal(result.value.savingDelivery, false)
      })
      .assert.cssProperty('.setting-table-card .setting-action-btn', 'color', 'rgba(51, 153, 255, 1)')
      .execute(function () {
        var element = document.querySelector('.setting-table-card .setting-action-btn')
        var style = window.getComputedStyle(element)
        return {
          borderRadius: parseFloat(style.borderRadius),
          borderTopColor: style.borderTopColor,
          borderRightColor: style.borderRightColor,
          borderBottomColor: style.borderBottomColor,
          borderLeftColor: style.borderLeftColor,
          width: parseFloat(style.width),
          height: parseFloat(style.height)
        }
      }, [], function (result) {
        browser.assert.ok(result.value.borderRadius > 100, `button border radius is ${result.value.borderRadius}`)
        browser.assert.ok(result.value.borderTopColor.indexOf('51, 153, 255') !== -1, `border top color is ${result.value.borderTopColor}`)
        browser.assert.ok(result.value.borderRightColor.indexOf('51, 153, 255') !== -1, `border right color is ${result.value.borderRightColor}`)
        browser.assert.ok(result.value.borderBottomColor.indexOf('51, 153, 255') !== -1, `border bottom color is ${result.value.borderBottomColor}`)
        browser.assert.ok(result.value.borderLeftColor.indexOf('51, 153, 255') !== -1, `border left color is ${result.value.borderLeftColor}`)
        browser.assert.ok(result.value.width >= 32 && result.value.width <= 35, `button width is ${result.value.width}`)
        browser.assert.ok(result.value.height >= 30 && result.value.height <= 35, `button height is ${result.value.height}`)
      })
      .saveScreenshot('tests/e2e/reports/email-template-management-action.png')
      .end()
  },

  'Edit Invite Email exposes Status and persists template state': function (browser) {
    browser
      .resizeWindow(1440, 1200)
      .url(`${appUrl}/pages/login`)
      .waitForElementVisible('body', 5000)
    bootstrapAuthenticatedRoute(browser, {
      route: '/config/email-notifications',
      permissions: {
        '/accounts/directory': { all: true, view: true, edit: true, action: true, delete: true },
        '/config/message-authen': { all: true, view: true, edit: true, action: true, delete: true },
        '/config/email-notifications': { all: true, view: true, edit: true, action: true, delete: true }
      }
    })
    browser
      .waitForElementVisible('.email-notification-page', 20000)
      .waitForElementVisible('.setting-table-card .setting-action-btn', 10000)
      .click('.setting-table-card .setting-action-btn')
      .waitForElementVisible('.login-message-modal', 10000)
      .assert.containsText('.login-message-modal', 'Edit Invite Email')
      .assert.containsText('.login-message-modal', 'State')
      .execute(function () {
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
        var modal = null
        Array.prototype.some.call(document.querySelectorAll('*'), function (node) {
          modal = findComponent(node.__vue__, 'EmailNotificationTemplateModal')
          return !!modal
        })
        return modal ? modal.statusOptions.map(function (item) { return item.label }) : []
      }, [], function (result) {
        browser.assert.ok(result.value.some(function (text) { return text.indexOf('Active') !== -1 }))
        browser.assert.ok(result.value.some(function (text) { return text.indexOf('Inactive') !== -1 }))
      })
      .execute(function () {
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
        var modal = null
        Array.prototype.some.call(document.querySelectorAll('*'), function (node) {
          modal = findComponent(node.__vue__, 'EmailNotificationTemplateModal')
          return !!modal
        })
        if (!modal) return false
        modal.local.status = 'inactive'
        return true
      }, [], function (result) {
        browser.assert.equal(result.value, true)
      })
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
        var modal = null
        Array.prototype.some.call(document.querySelectorAll('*'), function (node) {
          page = page || findComponent(node.__vue__, 'EmailNotifications')
          modal = modal || findComponent(node.__vue__, 'EmailNotificationTemplateModal')
          return !!(page && modal)
        })
        if (!page || !modal) {
          done({ error: 'email_notification_components_not_found' })
          return
        }
        page.saveTemplate(Object.assign({}, modal.local, {
          text: modal.generatedHtml,
          html: modal.generatedHtml,
          status: modal.local.status
        })).then(function () {
          done({
            showTemplateModal: page.showTemplateModal,
            rowTexts: Array.prototype.map.call(document.querySelectorAll('.setting-table-card tbody tr'), function (row) {
              return row.textContent.replace(/\s+/g, ' ').trim()
            })
          })
        }).catch(function (error) {
          done({ error: error && error.message ? error.message : 'email_template_save_failed' })
        })
      }, [], function (result) {
        browser.assert.ok(!result.value.error, result.value.error || 'email template save succeeded')
        browser.assert.equal(result.value.showTemplateModal, false)
        browser.assert.ok((result.value.rowTexts || []).some(function (text) { return text.indexOf('Inactive') !== -1 }))
      })
      .saveScreenshot('tests/e2e/reports/email-template-management-active-state.png')
      .end()
  },

  'Workflow Actions page persists recipient settings': function (browser) {
    browser
      .resizeWindow(1440, 1200)
      .url(`${appUrl}/pages/login`)
      .waitForElementVisible('body', 5000)
    bootstrapAuthenticatedRoute(browser, {
      route: '/config/workflow-actions',
      permissions: {
        '/accounts/directory': { all: true, view: true, edit: true, action: true, delete: true },
        '/config/email-notifications': { all: true, view: true, edit: true, action: true, delete: true },
        '/config/workflow-actions': { all: true, view: true, edit: true, action: true, delete: true }
      }
    })
    browser
      .waitForElementVisible('.workflow-actions-page', 20000)
      .waitForElementVisible('.c-sidebar-nav a[href="/config/workflow-actions"]', 10000)
      .waitForElementVisible('.workflow-action-list__item', 10000)
      .assert.containsText('.workflow-actions-page', 'Workflow Actions')
      .assert.containsText('.workflow-actions-page', 'Invite Email')
      .assert.containsText('.workflow-actions-page', 'Payment paid')
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
          page = findComponent(node.__vue__, 'WorkflowActions')
          return !!page
        })
        if (!page) {
          done({ error: 'workflow_actions_page_not_found' })
          return
        }
        page.actionForm.recipientMode = 'context'
        page.actionForm.recipientValue = 'email'
        page.actionForm.conditionField = 'invited'
        page.saveAction().then(function () {
          done({
            eventKey: page.actionForm.eventKey,
            recipientMode: page.actionForm.recipientMode,
            recipientValue: page.actionForm.recipientValue,
            conditionField: page.actionForm.conditionField,
            saving: page.saving
          })
        }).catch(function (error) {
          done({ error: error && error.message ? error.message : 'workflow_action_save_failed' })
        })
      }, [], function (result) {
        browser.assert.ok(!result.value.error, result.value.error || 'workflow action save succeeded')
        browser.assert.equal(result.value.eventKey, 'account.invite')
        browser.assert.equal(result.value.recipientMode, 'context')
        browser.assert.equal(result.value.recipientValue, 'email')
        browser.assert.equal(result.value.conditionField, 'invited')
        browser.assert.equal(result.value.saving, false)
      })
      .saveScreenshot('tests/e2e/reports/workflow-actions-settings.png')
      .end()
  },

  'Custom Email Template appears in Workflow Actions': function (browser) {
    browser
      .resizeWindow(1440, 1200)
      .url(`${appUrl}/pages/login`)
      .waitForElementVisible('body', 5000)
    bootstrapAuthenticatedRoute(browser, {
      route: '/config/email-notifications',
      permissions: {
        '/accounts/directory': { all: true, view: true, edit: true, action: true, delete: true },
        '/config/email-notifications': { all: true, view: true, edit: true, action: true, delete: true },
        '/config/workflow-actions': { all: true, view: true, edit: true, action: true, delete: true }
      }
    })
    browser
      .waitForElementVisible('.email-notification-page', 20000)
      .waitForElementVisible('.setting-table-card .setting-add-btn', 10000)
      .click('.setting-table-card .setting-add-btn')
      .waitForElementVisible('.login-message-modal', 10000)
      .assert.containsText('.login-message-modal', 'Add Email Template')
      .assert.containsText('.login-message-modal', 'Event key')
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
        var modal = null
        Array.prototype.some.call(document.querySelectorAll('*'), function (node) {
          page = page || findComponent(node.__vue__, 'EmailNotifications')
          modal = modal || findComponent(node.__vue__, 'EmailNotificationTemplateModal')
          return !!(page && modal)
        })
        if (!page || !modal) {
          done({ error: 'custom_template_components_not_found' })
          return
        }
        modal.local.key = 'payment.expired'
        modal.local.label = 'Payment expired'
        modal.local.description = 'NewSystem notification when a payment expires.'
        modal.local.subject = 'Payment {paymentId} expired'
        modal.local.text = '<p>Payment {paymentId} expired for {amount} {currency}.</p>'
        modal.local.placeholdersText = 'paymentId, amount, currency'
        page.saveTemplate({
          isNew: true,
          key: 'payment.expired',
          eventKey: 'payment.expired',
          label: 'Payment expired',
          description: 'NewSystem notification when a payment expires.',
          subject: 'Payment {paymentId} expired',
          text: modal.generatedHtml,
          html: modal.generatedHtml,
          status: 'active',
          placeholders: ['paymentId', 'amount', 'currency'],
          hasWorkflowRecord: false
        }).then(function () {
          page.$nextTick(function () {
            done({
              showTemplateModal: page.showTemplateModal,
              rows: Array.prototype.map.call(document.querySelectorAll('.setting-table-card tbody tr'), function (row) {
                return row.textContent.replace(/\s+/g, ' ').trim()
              })
            })
          })
        }).catch(function (error) {
          done({ error: error && error.message ? error.message : 'custom_template_save_failed' })
        })
      }, [], function (result) {
        browser.assert.ok(!result.value.error, result.value.error || 'custom template save succeeded')
        browser.assert.equal(result.value.showTemplateModal, false)
        browser.assert.ok((result.value.rows || []).some(function (text) { return text.indexOf('Payment expired') !== -1 }), 'custom template row is visible')
      })
      .url(`${appUrl}/config/workflow-actions`)
      .waitForElementVisible('.workflow-actions-page', 20000)
      .waitForElementVisible('.workflow-action-list__item', 10000)
      .assert.containsText('.workflow-actions-page', 'Payment expired')
      .saveScreenshot('tests/e2e/reports/custom-email-template-workflow-action.png')
      .end()
  }
}

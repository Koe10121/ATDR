const appUrl = String(
  process.env.E2E_APP_URL ||
  process.env.TEST_APP_URL ||
  process.env.VUE_DEV_SERVER_URL ||
  'http://127.0.0.1:8080'
).replace(/\/$/, '')
const { bootstrapAuthenticatedRoute } = require('../support/newSystem-session')

module.exports = {
  'Account invite modal renders without style breakage': function (browser) {
    browser
      .resizeWindow(1440, 1400)
      .url(`${appUrl}/pages/login`)
      .waitForElementVisible('body', 5000)
    bootstrapAuthenticatedRoute(browser, {
      route: '/accounts/directory',
      permissions: {
        '/accounts/directory': { all: true, view: true, edit: true, action: true, delete: true }
      }
    })
    browser
      .waitForElementVisible('.account-table-card', 8000)
      .waitForElementVisible('.account-invite-btn', 5000)
      .click('.account-invite-btn')
      .waitForElementVisible('.account-invite-modal .modal-content', 5000)
      .assert.elementPresent('.account-invite-modal .account-modal__section')
      .assert.elementPresent('.account-invite-modal .floating-group')
      .assert.elementPresent('.account-invite-modal .floating-multi')
      .assert.cssProperty('.account-invite-modal .account-modal__section', 'border-radius', '16px')
      .assert.cssProperty('.account-invite-modal .account-modal__hero', 'display', 'block')
      .assert.not.cssProperty('.account-invite-modal .account-modal__hero', 'background-image', 'none')
      .assert.cssProperty('.account-invite-modal .account-modal__footer', 'display', 'flex')
      .assert.cssProperty('.account-invite-modal .account-modal__btn', 'border-radius', '999px')
      .setValue('.account-invite-modal input[type="email"]', 'invite.newSystem@example.com')
      .pause(300)
      .saveScreenshot('tests/e2e/reports/accounts-invite-modal.png')
      .end()
  }
}

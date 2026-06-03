// For authoring Nightwatch tests, see
// http://nightwatchjs.org/guide#usage

module.exports = {

  before: function (browser) {
    console.log('Setting up... browser', typeof browser)
  },

  after: function (browser) {
    console.log('Closing down... browser', typeof browser)
  },

  'Login page renders': function (browser) {
    const devServer = process.env.VUE_DEV_SERVER_URL

    browser
      .url(`${devServer}pages/login`)
      .waitForElementVisible('body', 5000)
      .waitForElementVisible('.c-app.flex-row', 5000)
      .assert.containsText('h3', 'Sign in')
      .assert.containsText('p.text-muted', 'Sign in with MFU Google account')
      .assert.elementPresent('img.google-btn')

    browser.end()
  }
}

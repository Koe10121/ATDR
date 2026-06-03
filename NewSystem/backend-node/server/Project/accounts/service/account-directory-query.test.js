'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const mongoose = require('mongoose');

require('./account');

test('account directory registers lifecycle models required by populate', function () {
    assert.equal(mongoose.modelNames().includes('Setting_Lifecycle_AffiliationType'), true);
    assert.equal(mongoose.modelNames().includes('Setting_Lifecycle_AccessProfile'), true);
});

'use strict';

const express = require('express');
const router = express.Router();

const account = require('../accounts/service/account');
const authorization = require('../security/service/authorization');
const category = require('./service/category');

const canViewCategory = authorization.requirePermission('/management/category', 'view');
const canEditCategory = authorization.requirePermission('/management/category', 'edit');
const canDeleteCategory = authorization.requirePermission('/management/category', 'delete');

router.use(account.onCheckAuthorization);

router.get('/', canViewCategory, category.onQuerys);
router.get('/one', canViewCategory, category.onQuery);
router.post('/', canEditCategory, category.onCreate);
router.put('/', canEditCategory, category.onUpdate);
router.delete('/', canDeleteCategory, category.onDelete);

module.exports = router;

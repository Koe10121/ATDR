'use strict';

const mongo = require('mongodb');
const Type = require('../controller/type');
const Menu = require('../controller/menu');
const Group = require('../controller/group');
const Permission = require('../controller/permission');
const GroupModel = require('../models/group.model');
const MenuModel = require('../models/menu.model');
const PermissionModel = require('../models/permission.model');
const resMsg = require('../../settings/service/message');

async function syncPermissions() {
    const groups = await GroupModel.find({}).select('_id visibleType').lean();
    const menus = await MenuModel.find({}).select('_id type').lean();

    const allowMap = new Set();
    const insertRows = [];

    for (const group of groups) {
        for (const menu of menus) {
            if (String(group.visibleType) !== String(menu.type)) continue;
            allowMap.add(`${group._id}:${menu._id}`);
        }
    }

    const current = await PermissionModel.find({}).select('_id group menu').lean();
    const currentMap = new Set(current.map(item => `${item.group}:${item.menu}`));

    for (const key of allowMap) {
        if (currentMap.has(key)) continue;
        const ids = key.split(':');
        insertRows.push({
            group: new mongo.ObjectId(ids[0]),
            menu: new mongo.ObjectId(ids[1]),
            all: false,
            view: false,
            edit: false,
            delete: false,
            action: false,
            logs: false
        });
    }

    if (insertRows.length) {
        await PermissionModel.insertMany(insertRows, { ordered: false });
    }

    const invalidIds = current
        .filter(item => !allowMap.has(`${item.group}:${item.menu}`))
        .map(item => item._id);

    if (invalidIds.length) {
        await PermissionModel.deleteMany({ _id: { $in: invalidIds } });
    }
}

exports.onBootstrap = async function (request, response, next) {
    try {
        await syncPermissions();

        const types = await Type.onQuerys({});
        const menus = await Menu.onQuerys({});
        const groups = await Group.onQuerys({});
        const permissions = await Permission.onQuerys({});

        var resData = await resMsg.onMessage_Response(0,20000)
        resData.data = { types, menus, groups, permissions }
        response.status(200).json(resData);
    } catch (err) {
        var resData = await resMsg.onMessage_Response(0,40400)
        response.status(404).json(resData);
    }
};

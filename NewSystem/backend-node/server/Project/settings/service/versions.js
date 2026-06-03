var mongo = require('mongodb');
var utils = require('../../../../helpers/utils');
var initialize = require('../../../../helpers/initialize');
const resMsg = require("../service/message");

exports.onVersion = function (request, response, next) {
    var startTime = utils.getTimeInMsec();
    var command = "onVersion";
    try {
        resMsgs.onMessage_Response(0,20000,function(res){
            var resData = res;
            response.status(200).json(resData);
            utils.writeLog(command, request, startTime, res, null)
        });
    }catch (err) {
        resMsgs.onMessage_Response(0,40100,function(res){
            var url = {}
            url.url = "https://www.google.co.th";
            var resData = res;
            resData.data = url;
            response.status(401).json(res);
        });
    }
};

exports.onBanners = function (request, response, next) {
    var startTime = utils.getTimeInMsec();
    var command = "onBanners";
    try {

        var objs = [
            {
                title: 'Earlier this morning, NYC',
                subtitle: 'Lorem ipsum dolor sit amet',
                illustration: 'https://api.finnext.io/images/banners/1.png',
            }, {
            title: 'Earlier this morning, NYC',
            subtitle: 'Lorem ipsum dolor sit amet',
            illustration: 'https://api.finnext.io/images/banners/2.png',
        }, {
            title: 'Earlier this morning, NYC',
            subtitle: 'Lorem ipsum dolor sit amet',
            illustration: 'https://api.finnext.io/images/banners/3.png',
        }, {
            title: 'Earlier this morning, NYC',
            subtitle: 'Lorem ipsum dolor sit amet',
            illustration: 'https://api.finnext.io/images/banners/4.png',
        }, {
            title: 'Earlier this morning, NYC',
            subtitle: 'Lorem ipsum dolor sit amet',
            illustration: 'https://api.finnext.io/images/banners/5.png',
        }
        ]
        resMsgs.onMessage_Response(0,20000,function(res){
            var resData = res;
            resData.data = objs;
            response.status(200).json(resData);
            utils.writeLog(command, request, startTime, res, null)
        });
    }catch (err) {
        resMsgs.onMessage_Response(0,40100,function(res){
            var url = {}
            url.url = "https://www.google.co.th";
            var resData = res;
            resData.data = url;
            response.status(401).json(res);
        });
    }
};


exports.onHotnews = function (request, response, next) {
    var startTime = utils.getTimeInMsec();
    var command = "onHotnews";
    try {
        var objs = {}
        objs.image = "https://api.finnext.io/images/news.jpg"
        resMsgs.onMessage_Response(0,20000,function(res){
            var resData = res;
            resData.data = objs;
            response.status(200).json(resData);
            utils.writeLog(command, request, startTime, res, null)
        });
    }catch (err) {
        resMsgs.onMessage_Response(0,40100,function(res){
            var url = {}
            url.url = "https://www.google.co.th";
            var resData = res;
            resData.data = url;
            response.status(401).json(res);
        });
    }
};


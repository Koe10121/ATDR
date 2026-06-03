/**
 * Created by atthapok on 24/06/2559.
 */

var msg = [];
msg[20000] = { code: 20000,httpcode: 200,message: [{value: "ทำรายการเรียบร้อย",key: "th"},{value: "Success",key: "en"}] };
msg[40300] = { code: 40300,httpcode: 403,message: [{value: "ข้อมูลไม่ครบ หรือข้อมูลผิดพลาด",key: "th"},{value: "Missing or invalid parameter",key: "en"}] };
msg[40301] = { code: 40301,httpcode: 403,message: [{value: "มีข้อมูลนี้อยู่แล้ว",key: "th"},{value: "Data is duplicated",key: "en"}] };
msg[40400] = { code: 40400,httpcode: 404,message: [{value: "ไม่พบข้อมูลนี้ในระบบ",key: "th"},{value: "Data not found",key: "en"}] };

var responseMsg = {};
responseMsg.getMsg = function (code) {
    return msg[code];
}

module.exports = responseMsg;

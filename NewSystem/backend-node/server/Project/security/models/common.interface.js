'use strict';

exports.multiLanguageInterface = {
  key: { type: String, default: null },
  value: { type: String, default: null }
};

exports.getAuditInterface = function (Schema) {
  return {
    by: { type: Schema.ObjectId, default: null },
    at: { type: Date, default: null }
  };
};

exports.getCreatedDefault = function () {
  return { at: new Date() };
};

exports.getUpdatedDefault = function () {
  return { at: null };
};

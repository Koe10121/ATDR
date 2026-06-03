'use strict';

const mongo = require('mongodb');

function resolveActorObjectId(request, payload) {
  const authAccountId = request && request.authAccount && request.authAccount._id
    ? String(request.authAccount._id)
    : '';
  if (authAccountId && mongo.ObjectId.isValid(authAccountId)) {
    return new mongo.ObjectId(authAccountId);
  }

  const payloadAccountId = payload && payload.accounts ? String(payload.accounts) : '';
  if (payloadAccountId && mongo.ObjectId.isValid(payloadAccountId)) {
    return new mongo.ObjectId(payloadAccountId);
  }

  return null;
}

async function attachAudit(request, payload, type) {
  if (!payload) return payload;
  const actorId = resolveActorObjectId(request, payload);
  if (!actorId) return payload;
  payload[type] = Object.assign({}, payload[type] || {}, {
    by: actorId,
    datetime: new Date()
  });
  return payload;
}

module.exports = {
  resolveActorObjectId,
  attachAudit
};

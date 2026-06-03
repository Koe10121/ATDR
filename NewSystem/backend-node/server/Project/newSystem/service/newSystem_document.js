'use strict';

const mongoose = require('mongoose');
const NewSystemDocument = require('../models/newSystem_document.model');

const DEFAULT_LIMIT = 50;
const MAX_LIMIT = 200;

function toNumber(value, fallback) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function normalizeStatus(status) {
  return String(status || '').trim().toLowerCase();
}

function cleanText(value) {
  const normalized = String(value || '').trim();
  return normalized || null;
}

function cleanDate(value) {
  if (!value) return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

function cleanTags(value) {
  if (Array.isArray(value)) {
    return value.map(cleanText).filter(Boolean);
  }
  return String(value || '')
    .split(',')
    .map(cleanText)
    .filter(Boolean);
}

function actorFromRequest(request) {
  const account = request.currentAccount || request.account || request.user || {};
  return {
    by: account._id || account.id || null,
    name: account.name || account.fullName || account.displayName || null,
    email: account.email || null,
    datetime: new Date()
  };
}

function payloadFromBody(body) {
  const payload = {
    newSystemNo: cleanText(body.newSystemNo),
    title: cleanText(body.title),
    partnerName: cleanText(body.partnerName),
    partnerType: cleanText(body.partnerType) || 'University',
    country: cleanText(body.country) || 'Thailand',
    ownerUnit: cleanText(body.ownerUnit),
    coordinatorName: cleanText(body.coordinatorName),
    coordinatorEmail: cleanText(body.coordinatorEmail),
    status: normalizeStatus(body.status) || 'draft',
    effectiveDate: cleanDate(body.effectiveDate),
    expiryDate: cleanDate(body.expiryDate),
    renewalNoticeDate: cleanDate(body.renewalNoticeDate),
    documentUrl: cleanText(body.documentUrl),
    tags: cleanTags(body.tags),
    notes: cleanText(body.notes)
  };

  Object.keys(payload).forEach(function (key) {
    if (payload[key] === null || payload[key] === undefined || payload[key] === '') {
      delete payload[key];
    }
  });

  return payload;
}

function buildListQuery(query) {
  const filter = {};
  const q = cleanText(query.q);
  const status = normalizeStatus(query.status);
  const ownerUnit = cleanText(query.ownerUnit);
  const expiringDays = toNumber(query.expiringDays, 0);

  if (q) {
    filter.$or = [
      { newSystemNo: new RegExp(q, 'i') },
      { title: new RegExp(q, 'i') },
      { partnerName: new RegExp(q, 'i') },
      { ownerUnit: new RegExp(q, 'i') },
      { tags: new RegExp(q, 'i') }
    ];
  }
  if (status && status !== 'all') filter.status = status;
  if (ownerUnit) filter.ownerUnit = ownerUnit;
  if (expiringDays > 0) {
    const now = new Date();
    const until = new Date(now.getTime() + expiringDays * 86400000);
    filter.expiryDate = { $gte: now, $lte: until };
  }

  return filter;
}

function updateLifecycleStatus(doc) {
  if (!doc || !doc.expiryDate || doc.status === 'archived') return doc;
  const now = new Date();
  const expiry = new Date(doc.expiryDate);
  const expiringFrom = new Date(now.getTime() + 90 * 86400000);

  if (expiry < now) {
    doc.status = 'expired';
  } else if (expiry <= expiringFrom && doc.status === 'active') {
    doc.status = 'expiring';
  }
  return doc;
}

exports.list = async function list(query) {
  const page = Math.max(toNumber(query.page, 1), 1);
  const limit = Math.min(Math.max(toNumber(query.limit, DEFAULT_LIMIT), 1), MAX_LIMIT);
  const skip = (page - 1) * limit;
  const filter = buildListQuery(query || {});

  const [rows, total] = await Promise.all([
    NewSystemDocument.find(filter).sort({ expiryDate: 1, updatedAt: -1 }).skip(skip).limit(limit).lean(),
    NewSystemDocument.countDocuments(filter)
  ]);

  return {
    rows,
    total,
    page,
    limit,
    hasMore: skip + rows.length < total
  };
};

exports.stats = async function stats() {
  const now = new Date();
  const next90 = new Date(now.getTime() + 90 * 86400000);
  const [total, active, review, expiring, expired] = await Promise.all([
    NewSystemDocument.countDocuments({}),
    NewSystemDocument.countDocuments({ status: 'active' }),
    NewSystemDocument.countDocuments({ status: 'review' }),
    NewSystemDocument.countDocuments({
      $or: [
        { status: 'expiring' },
        { expiryDate: { $gte: now, $lte: next90 } }
      ]
    }),
    NewSystemDocument.countDocuments({
      $or: [
        { status: 'expired' },
        { expiryDate: { $lt: now } }
      ]
    })
  ]);

  return { total, active, review, expiring, expired };
};

exports.create = async function create(body, request) {
  const payload = payloadFromBody(body || {});
  const missing = ['newSystemNo', 'title', 'partnerName'].filter(function (field) {
    return !payload[field];
  });
  if (missing.length) {
    const error = new Error('Missing required fields: ' + missing.join(', '));
    error.status = 400;
    throw error;
  }
  payload.create = actorFromRequest(request || {});

  const created = await NewSystemDocument.create(updateLifecycleStatus(payload));
  return created.toObject();
};

exports.update = async function update(id, body, request) {
  if (!mongoose.Types.ObjectId.isValid(id)) {
    const error = new Error('Invalid NewSystem document id');
    error.status = 400;
    throw error;
  }

  const payload = payloadFromBody(body || {});
  payload.update = actorFromRequest(request || {});
  const updated = await NewSystemDocument.findOneAndUpdate(
    { _id: new mongoose.Types.ObjectId(id) },
    updateLifecycleStatus(payload),
    { new: true, runValidators: true }
  ).lean();

  if (!updated) {
    const error = new Error('NewSystem document not found');
    error.status = 404;
    throw error;
  }
  return updated;
};

exports.remove = async function remove(id) {
  if (!mongoose.Types.ObjectId.isValid(id)) {
    const error = new Error('Invalid NewSystem document id');
    error.status = 400;
    throw error;
  }

  const result = await NewSystemDocument.deleteOne({ _id: new mongoose.Types.ObjectId(id) });
  return { deleted: result.deletedCount || 0 };
};

exports.seedDemo = async function seedDemo(request) {
  const existing = await NewSystemDocument.countDocuments({});
  if (existing > 0) {
    return { skipped: true, total: existing };
  }

  const actor = actorFromRequest(request || {});
  const today = new Date();
  const monthsFromNow = function (months) {
    const date = new Date(today);
    date.setMonth(date.getMonth() + months);
    return date;
  };

  await NewSystemDocument.insertMany([
    {
      newSystemNo: 'NewSystem-INT-2026-001',
      title: 'Academic Collaboration and Exchange',
      partnerName: 'Mae Fah Luang University Partner Network',
      partnerType: 'University',
      country: 'Thailand',
      ownerUnit: 'International Affairs Division',
      coordinatorName: 'NewSystem Coordinator',
      coordinatorEmail: 'newSystem@mfu.ac.th',
      status: 'active',
      effectiveDate: today,
      expiryDate: monthsFromNow(30),
      renewalNoticeDate: monthsFromNow(27),
      tags: ['academic', 'exchange'],
      notes: 'Initial demo record for validating NewSystem workflows.',
      create: actor
    },
    {
      newSystemNo: 'NewSystem-RES-2026-002',
      title: 'Research Collaboration Framework',
      partnerName: 'Regional Research Institute',
      partnerType: 'Institute',
      country: 'Thailand',
      ownerUnit: 'Research and Innovation Office',
      coordinatorName: 'Research Coordinator',
      coordinatorEmail: 'research@mfu.ac.th',
      status: 'review',
      effectiveDate: today,
      expiryDate: monthsFromNow(18),
      renewalNoticeDate: monthsFromNow(15),
      tags: ['research'],
      create: actor
    },
    {
      newSystemNo: 'NewSystem-EXP-2026-003',
      title: 'Student Mobility Agreement',
      partnerName: 'Global Mobility Partner',
      partnerType: 'University',
      country: 'Japan',
      ownerUnit: 'School of Management',
      coordinatorName: 'Mobility Coordinator',
      coordinatorEmail: 'mobility@mfu.ac.th',
      status: 'active',
      effectiveDate: today,
      expiryDate: monthsFromNow(2),
      renewalNoticeDate: monthsFromNow(1),
      tags: ['student', 'mobility'],
      create: actor
    }
  ]);

  return { skipped: false, total: 3 };
};

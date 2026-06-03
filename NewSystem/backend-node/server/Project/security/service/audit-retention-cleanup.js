'use strict';

const AUDIT_COLLECTION = 'Security_AuditEvent';

function pad(value) {
  return String(value).padStart(2, '0');
}

function formatBatchId(date) {
  const current = date instanceof Date ? date : new Date();
  return [
    current.getUTCFullYear(),
    pad(current.getUTCMonth() + 1),
    pad(current.getUTCDate()),
    'T',
    pad(current.getUTCHours()),
    pad(current.getUTCMinutes()),
    pad(current.getUTCSeconds()),
    'Z'
  ].join('');
}

function buildArchiveCollectionName(batchId) {
  return `Archive_${AUDIT_COLLECTION}_${batchId}`;
}

function resolveCutoffDate(retentionDays, now) {
  const normalizedDays = Number(retentionDays);
  if (!Number.isFinite(normalizedDays) || normalizedDays < 0) {
    throw new Error('invalid_retention_days');
  }
  const current = now instanceof Date ? now : new Date();
  return new Date(current.getTime() - (normalizedDays * 24 * 60 * 60 * 1000));
}

async function cleanupAuditRetention(db, options) {
  const settings = Object.assign({
    execute: false,
    retentionDays: 90
  }, options || {});

  const batchId = settings.batchId || formatBatchId(new Date());
  const cutoffDate = resolveCutoffDate(settings.retentionDays, settings.now);
  const archiveCollection = buildArchiveCollectionName(batchId);
  const sourceCollection = AUDIT_COLLECTION;
  const query = { createdAt: { $lt: cutoffDate } };

  const totalCount = await db.collection(sourceCollection).countDocuments();
  const eligibleDocs = await db.collection(sourceCollection).find(query).toArray();
  const eligibleCount = eligibleDocs.length;

  const summary = {
    execute: !!settings.execute,
    batchId: batchId,
    retentionDays: Number(settings.retentionDays),
    cutoffDate: cutoffDate.toISOString(),
    sourceCollection: sourceCollection,
    archiveCollection: archiveCollection,
    totalCount: totalCount,
    eligibleCount: eligibleCount,
    archivedCount: 0,
    deletedCount: 0,
    status: eligibleCount > 0 ? 'dry-run' : 'no-op'
  };

  if (!settings.execute || eligibleCount === 0) {
    return summary;
  }

  const existingCollections = await db.listCollections({ name: archiveCollection }, { nameOnly: true }).toArray();
  if (existingCollections.length > 0) {
    throw new Error(`archive_collection_already_exists:${archiveCollection}`);
  }

  const archivedAt = new Date();
  const archiveDocs = eligibleDocs.map(function (doc) {
    return {
      archiveBatchId: batchId,
      archivedAt: archivedAt,
      sourceCollection: sourceCollection,
      sourceId: doc && doc._id ? doc._id : null,
      payload: doc
    };
  });

  await db.collection(archiveCollection).insertMany(archiveDocs, { ordered: true });
  summary.archivedCount = archiveDocs.length;
  if (summary.archivedCount !== eligibleCount) {
    throw new Error('audit_archive_count_mismatch');
  }

  const deleteResult = await db.collection(sourceCollection).deleteMany({
    _id: { $in: eligibleDocs.map(function (doc) { return doc._id; }) }
  });
  summary.deletedCount = deleteResult.deletedCount || 0;
  if (summary.deletedCount !== eligibleCount) {
    throw new Error('audit_delete_count_mismatch');
  }

  summary.status = 'archived_and_purged';
  return summary;
}

module.exports = {
  AUDIT_COLLECTION,
  buildArchiveCollectionName,
  resolveCutoffDate,
  cleanupAuditRetention
};

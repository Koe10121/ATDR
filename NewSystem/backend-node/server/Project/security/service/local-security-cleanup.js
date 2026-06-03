'use strict';

const TARGET_COLLECTIONS = [
  'Security_Type',
  'Security_Menu',
  'Security_Group',
  'Security_Permission',
  'Security_Assignment'
];

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

function buildArchiveCollectionName(sourceCollection, batchId) {
  return `Archive_${sourceCollection}_${batchId}`;
}

async function archiveCollectionDocs(db, sourceCollection, archiveCollectionName, batchId, archivedAt) {
  const sourceDocs = await db.collection(sourceCollection).find({}).toArray();
  const sourceCount = sourceDocs.length;

  if (sourceCount === 0) {
    return {
      sourceCollection,
      archiveCollection: archiveCollectionName,
      sourceCount: 0,
      archivedCount: 0,
      deletedCount: 0,
      status: 'empty'
    };
  }

  const archiveDocs = sourceDocs.map(function (doc) {
    return {
      archiveBatchId: batchId,
      archivedAt: archivedAt,
      sourceCollection: sourceCollection,
      sourceId: doc && doc._id ? doc._id : null,
      payload: doc
    };
  });

  await db.collection(archiveCollectionName).insertMany(archiveDocs, { ordered: true });

  return {
    sourceCollection,
    archiveCollection: archiveCollectionName,
    sourceCount: sourceCount,
    archivedCount: archiveDocs.length,
    deletedCount: 0,
    status: 'archived'
  };
}

async function cleanupLocalSecurityOwnership(db, options) {
  const settings = Object.assign({
    execute: false,
    includeCollections: TARGET_COLLECTIONS,
    dryRunLabel: 'dry-run'
  }, options || {});

  const batchId = settings.batchId || formatBatchId(new Date());
  const archivedAt = new Date();
  const collections = Array.isArray(settings.includeCollections) && settings.includeCollections.length
    ? settings.includeCollections.slice()
    : TARGET_COLLECTIONS.slice();

  const existingCollections = await db.listCollections({}, { nameOnly: true }).toArray();
  const existingNames = new Set(existingCollections.map(function (item) { return item.name; }));

  const summary = {
    execute: !!settings.execute,
    batchId: batchId,
    archivedAt: archivedAt.toISOString(),
    targets: [],
    totals: {
      sourceCount: 0,
      archivedCount: 0,
      deletedCount: 0
    }
  };

  for (const sourceCollection of collections) {
    const archiveCollection = buildArchiveCollectionName(sourceCollection, batchId);
    if (!existingNames.has(sourceCollection)) {
      summary.targets.push({
        sourceCollection,
        archiveCollection,
        sourceCount: 0,
        archivedCount: 0,
        deletedCount: 0,
        status: 'missing'
      });
      continue;
    }

    const sourceCount = await db.collection(sourceCollection).countDocuments();
    if (!settings.execute) {
      summary.targets.push({
        sourceCollection,
        archiveCollection,
        sourceCount,
        archivedCount: 0,
        deletedCount: 0,
        status: sourceCount > 0 ? settings.dryRunLabel : 'empty'
      });
      summary.totals.sourceCount += sourceCount;
      continue;
    }

    if (existingNames.has(archiveCollection)) {
      throw new Error(`archive_collection_already_exists:${archiveCollection}`);
    }

    const targetSummary = await archiveCollectionDocs(db, sourceCollection, archiveCollection, batchId, archivedAt);
    summary.totals.sourceCount += targetSummary.sourceCount;
    summary.totals.archivedCount += targetSummary.archivedCount;

    if (targetSummary.sourceCount > 0) {
      if (targetSummary.archivedCount !== targetSummary.sourceCount) {
        throw new Error(`archive_count_mismatch:${sourceCollection}`);
      }
      const deleteResult = await db.collection(sourceCollection).deleteMany({});
      targetSummary.deletedCount = deleteResult.deletedCount || 0;
      summary.totals.deletedCount += targetSummary.deletedCount;
      if (targetSummary.deletedCount !== targetSummary.sourceCount) {
        throw new Error(`delete_count_mismatch:${sourceCollection}`);
      }
      targetSummary.status = 'archived_and_purged';
    }

    summary.targets.push(targetSummary);
  }

  return summary;
}

module.exports = {
  TARGET_COLLECTIONS,
  formatBatchId,
  buildArchiveCollectionName,
  cleanupLocalSecurityOwnership
};

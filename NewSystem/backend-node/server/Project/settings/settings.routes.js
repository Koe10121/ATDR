const express = require('express');
const router = express.Router();
const account = require('../accounts/service/account');
const authorization = require('../security/service/authorization');

const message = require("./service/message");
const status = require("./service/status");
const group = require("./service/group");
const verification = require("./service/verification");
const authMessage = require("./service/auth_message");
const emailNotification = require("./service/email_notification");
const emailDelivery = require("./service/email_delivery");
const emailWorkflow = require("./service/email_workflow");
const runtimeAccess = require("./service/runtime_access");
const databaseBackup = require("./service/database_backup");

const canViewSettingMessage = authorization.requirePermission('/config/setting-message', 'view');
const canEditSettingMessage = authorization.requirePermission('/config/setting-message', 'edit');
const canDeleteSettingMessage = authorization.requirePermission('/config/setting-message', 'delete');
const canViewStatus = authorization.requirePermission('/setting/message-status', 'view');
const canEditStatus = authorization.requirePermission('/setting/message-status', 'edit');
const canDeleteStatus = authorization.requirePermission('/setting/message-status', 'delete');
const canViewGroup = authorization.requirePermission('/setting/group', 'view');
const canEditGroup = authorization.requirePermission('/setting/group', 'edit');
const canDeleteGroup = authorization.requirePermission('/setting/group', 'delete');
const canViewVerification = authorization.requirePermission('/config/verification', 'view');
const canEditVerification = authorization.requirePermission('/config/verification', 'edit');
const canDeleteVerification = authorization.requirePermission('/config/verification', 'delete');
const canViewAuthMessage = authorization.requirePermission('/config/message-authen', 'view');
const canEditAuthMessage = authorization.requirePermission('/config/message-authen', 'edit');
const canDeleteAuthMessage = authorization.requirePermission('/config/message-authen', 'delete');
const canViewEmailNotifications = authorization.requirePermission('/config/email-notifications', 'view');
const canEditEmailNotifications = authorization.requirePermission('/config/email-notifications', 'edit');
const canDeleteEmailNotifications = authorization.requirePermission('/config/email-notifications', 'delete');
const canViewEmailWorkflow = authorization.requirePermission(['/config/email-notifications', '/config/workflow-actions'], 'view');
const canEditEmailWorkflow = authorization.requirePermission(['/config/email-notifications', '/config/workflow-actions'], 'edit');
const canDeleteEmailWorkflow = authorization.requirePermission(['/config/email-notifications', '/config/workflow-actions'], 'delete');
const canViewRuntimeAccess = authorization.requirePermission('/config/runtime-access', 'view');
const canEditRuntimeAccess = authorization.requirePermission('/config/runtime-access', 'edit');
const canActionRuntimeAccess = authorization.requirePermission('/config/runtime-access', 'action');
const canViewDatabaseBackup = authorization.requirePermission('/config/database-backup', 'view');
const canEditDatabaseBackup = authorization.requirePermission('/config/database-backup', 'edit');
const canDeleteDatabaseBackup = authorization.requirePermission('/config/database-backup', 'delete');
const canActionDatabaseBackup = authorization.requirePermission('/config/database-backup', 'action');

router.use(account.onCheckAuthorization);

router.get("/message", canViewSettingMessage, message.onQuerys);
router.post("/message", canEditSettingMessage, message.onCreate);
router.put("/message", canEditSettingMessage, message.onUpdate);
router.delete("/message", canDeleteSettingMessage, message.onDelete);

router.get("/status", canViewStatus, status.onQuerys);
router.post("/status", canEditStatus, status.onCreate);
router.put("/status", canEditStatus, status.onUpdate);
router.delete("/status", canDeleteStatus, status.onDelete);

router.get("/groups", canViewGroup, group.onQuerys);
router.post("/groups", canEditGroup, group.onCreate);
router.put("/groups", canEditGroup, group.onUpdate);
router.delete("/groups", canDeleteGroup, group.onDelete);

router.get("/verification", canViewVerification, verification.onQuerys);
router.post("/verification/explorers", canEditVerification, verification.onCreate);
router.post("/verification", canEditVerification, verification.onCreate);
router.put("/verification", canEditVerification, verification.onUpdate);
router.delete("/verification", canDeleteVerification, verification.onDelete);

router.get("/auth/message", canViewAuthMessage, authMessage.onQuerys);
router.post("/auth/message", canEditAuthMessage, authMessage.onCreate);
router.put("/auth/message", canEditAuthMessage, authMessage.onUpdate);
router.delete("/auth/message", canDeleteAuthMessage, authMessage.onDelete);
router.get("/email-notifications", canViewEmailNotifications, emailNotification.onGet);
router.put("/email-notifications", canEditEmailNotifications, emailNotification.onUpdate);
router.get("/email-delivery", canViewEmailNotifications, emailDelivery.onGet);
router.put("/email-delivery", canEditEmailNotifications, emailDelivery.onUpdate);
router.get("/email-workflows/definitions", canViewEmailWorkflow, emailWorkflow.onDefinitions);
router.get("/email-workflows", canViewEmailWorkflow, emailWorkflow.onQuerys);
router.post("/email-workflows", canEditEmailWorkflow, emailWorkflow.onCreate);
router.put("/email-workflows", canEditEmailWorkflow, emailWorkflow.onUpdate);
router.delete("/email-workflows", canDeleteEmailWorkflow, emailWorkflow.onDelete);
router.get("/runtime-access", canViewRuntimeAccess, runtimeAccess.onGet);
router.put("/runtime-access", canEditRuntimeAccess, runtimeAccess.onUpdate);
router.delete("/runtime-access/blocked-ip", canActionRuntimeAccess, runtimeAccess.onUnblockIp);
router.get("/database-backup", canViewDatabaseBackup, databaseBackup.onGet);
router.put("/database-backup", canEditDatabaseBackup, databaseBackup.onUpdate);
router.post("/database-backup/run", canActionDatabaseBackup, databaseBackup.onRun);
router.get("/database-backup/collections", canViewDatabaseBackup, databaseBackup.onCollections);
router.get("/database-backup/:id/preview", canViewDatabaseBackup, databaseBackup.onPreview);
router.post("/database-backup/:id/restore", canActionDatabaseBackup, databaseBackup.onRestore);
router.get("/database-backup/:id/download", canActionDatabaseBackup, databaseBackup.onDownload);
router.delete("/database-backup/:id", canDeleteDatabaseBackup, databaseBackup.onDelete);

module.exports = router;

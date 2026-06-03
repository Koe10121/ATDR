import axios from 'axios';
import store from '@/store/store'
import { removeItem } from '@/utils/db';
import router from '@/router/index'
const instance = axios.create();
let handlingUnauthorized = false;
const X_ACCESS_TOKEN_STORAGE_KEY = 'x-access-token';

const defaultApiBaseUrl = typeof window !== 'undefined' && window.location && window.location.hostname
  ? `http://${window.location.hostname}:8082`
  : 'http://127.0.0.1:8097';

instance.defaults.baseURL = process.env.VUE_APP_API_BASE_URL || defaultApiBaseUrl;
instance.defaults.withCredentials = true;

instance.defaults.headers = {
  "Content-Type": "application/json",
}

function getStoredAccessToken () {
      if (typeof window === 'undefined' || !window.localStorage) return '';
      const token = window.localStorage.getItem(X_ACCESS_TOKEN_STORAGE_KEY);
      return token && String(token).trim() ? String(token).trim() : '';
}

function clearStoredSession () {
      removeItem('objs').catch(function () {});
      if (typeof window !== 'undefined' && window.localStorage) {
        window.localStorage.removeItem(X_ACCESS_TOKEN_STORAGE_KEY);
      }
      store.commit('set', ['XAccessToken', '']);
      store.commit('auth/authenticated', { isAuthen: false, isOAuth: false });
      store.commit('auth/profile', null);
      store.commit('auth/isSignIn', true);
      store.commit('auth/is2FA', false);
      store.commit('auth/pendingToken', '');
      store.commit('security/reset');
}

instance.interceptors.request.use(
    (config) => {
      const token = store.state.XAccessToken
        ? String(store.state.XAccessToken).trim()
        : getStoredAccessToken();
      if (token) {
        if (!store.state.XAccessToken) {
          store.commit('set', ['XAccessToken', token]);
        }
        config.headers.Authorization = `Bearer ${token}`;
        config.headers['x-access-token'] = token;
      }

      config.headers.lang  = `${store.getters['setting/lang']}`;
      return config;
    },
    (error) => {
      return Promise.reject(error);
    }
);

instance.interceptors.response.use(
    (response) => {
      return response;
    },
    (error) => {
      if (error.response && error.response.status === 401) {
        const config = error.config || {};
        if (config.__skipAuthFailureCleanup) {
          return Promise.reject(error);
        }

        clearStoredSession();
        if (config.__skipAuthFailureRedirect) {
          return Promise.reject(error);
        }

        const currentPath = router && router.currentRoute && router.currentRoute.path
          ? String(router.currentRoute.path)
          : '';
        const isPublicPage = currentPath.startsWith('/pages');
        if (!handlingUnauthorized && !isPublicPage && currentPath !== '/pages/login') {
          handlingUnauthorized = true;
          router.push('/pages/login').catch(function () {}).finally(function () {
            handlingUnauthorized = false;
          });
        }
      }
      return Promise.reject(error);
    }
);

export default {
  campus(method, data) {
    switch (method){
      case 'exp':
        return instance.post("/api/v1/setting/explore/campus",data);
      case 'get':
        return instance.get("/api/v1/setting/campus");
      case 'post':
        delete data._id;
        return instance.post("/api/v1/setting/campus", data);
      case 'put':
        return instance.put("/api/v1/setting/campus", data);
      case 'delete':
        return instance.delete("/api/v1/setting/campus");
      default:
        break;
    }
  },

  facultys(method, data) {
    switch (method){
      case 'get':
        return instance.get("/api/v1/setting/faculty");
      case 'post':
        delete data._id;
        return instance.post("/api/v1/setting/faculty", data);
      case 'put':
        return instance.put("/api/v1/setting/faculty", data);
      case 'delete':
        return instance.delete("/api/v1/setting/faculty");
      default:
        break;
    }
  },

  departments(method, data) {
    switch (method){
      case 'exp':
        return instance.post("/api/v1/explore/departments",data);
      case 'get':
        return instance.get("/api/v1/setting/department");
      case 'post':
        delete data._id;
        return instance.post("/api/v1/setting/department", data);
      case 'put':
        return instance.put("/api/v1/setting/department", data);
      case 'delete':
        return instance.delete("/api/v1/setting/department");
      default:
        break;
    }
  },

  members(method, data) {
    switch (method){
      case 'exp':
        return instance.post("/api/v1/explore/profile",data);
      default:
        break;
    }
  },

  roles(method, data) {
    switch (method){
      case 'exp':
        return instance.get("/api/v1/setting/role",data);
      case 'post':
        return instance.post("/api/v1/setting/role",data);
      case 'put':
        return instance.put("/api/v1/setting/role",data);
      default:
        break;
    }
  },

  authenticated(method, data) {
    switch (method){
      case 'signin':
        return instance.post("/api/v1/signin",data);
      case 'twofa-request':
        return instance.post("/api/v1/auth/2fa/request", data || {});
      case 'twofa-verify':
        return instance.post("/api/v1/auth/2fa/verify", data || {});
      case 'trust-device':
        return instance.post("/api/v1/auth/trust-device", data || {});
      case 'me':
        return instance.get("/api/v1/auth/me");
      case 'me-silent':
        return instance.get("/api/v1/auth/me", {
          __skipAuthFailureCleanup: true,
          __skipAuthFailureRedirect: true
        });
      case 'sessions':
        return instance.get('/api/v1/auth/sessions');
      case 'revoke-session':
        return instance.delete(`/api/v1/auth/sessions/${data && data.id}`);
      case 'logout':
        return instance.post('/api/v1/auth/logout', data || {});
      case 'logout-all':
        return instance.post('/api/v1/auth/logout-all', data || {});
      case 'trusted-devices':
        return instance.get('/api/v1/auth/trusted-devices');
      case 'revoke-trusted-device':
        return instance.delete(`/api/v1/auth/trusted-devices/${data && data.id}`);
      case 'message':
        return instance.get("/api/v1/setting/auth/message",data);
      case 'create-message':
        return instance.post("/api/v1/setting/auth/message",data);
      case 'update-message':
        return instance.put("/api/v1/setting/auth/message",data);
      case 'remove-message':
        return instance.delete("/api/v1/setting/auth/message", { data: data || {} });
      default:
        break;
    }
  },

  accounts(method, data) {
    switch (method) {
      case 'list':
        return instance.get('/api/v1/accounts', { params: data || {} });
      case 'invite':
        return instance.post('/api/v1/accounts/invite', data || {});
      case 'update':
        return instance.put(`/api/v1/accounts/${data && (data.id || data._id)}`, data || {});
      case 'remove-newSystem-access':
        return instance.delete(`/api/v1/accounts/${data && (data.id || data._id)}/newSystem-access`);
      case 'lifecycle':
        return instance.get(`/api/v1/accounts/${data && (data.id || data._id)}/lifecycle`, { params: data || {} });
      case 'update-lifecycle':
        return instance.put(`/api/v1/accounts/${data && (data.id || data._id)}/lifecycle`, data || {});
      case 'provision':
        return instance.post(`/api/v1/accounts/${data && (data.id || data._id)}/provision`, data || {});
      case 'deprovision':
        return instance.post(`/api/v1/accounts/${data && (data.id || data._id)}/deprovision`, data || {});
      case 'group-options':
        return instance.get('/api/v1/accounts/group/options', { params: data || {} });
      case 'effective-permissions':
        return instance.get(`/api/v1/accounts/${data && (data.id || data._id)}/effective-permissions`, { params: data || {} });
      case 'sessions':
        return instance.get(`/api/v1/accounts/${data && (data.id || data._id)}/sessions`, { params: data || {} });
      case 'revoke-session':
        return instance.delete(`/api/v1/accounts/${data && (data.id || data._id)}/sessions/${data && data.sessionId}`);
      case 'trusted-devices':
        return instance.get(`/api/v1/accounts/${data && (data.id || data._id)}/trusted-devices`, { params: data || {} });
      case 'revoke-trusted-device':
        return instance.delete(`/api/v1/accounts/${data && (data.id || data._id)}/trusted-devices/${data && data.trustedDeviceId}`);
      case 'status-options':
        return instance.get('/api/v1/accounts/status/options', { params: data || {} });
      case 'change-status':
        return instance.put(`/api/v1/accounts/${data && (data.id || data._id)}/status`, data || {});
      default:
        break;
    }
  },


  chat(userId, message) {
    return instance.post('/api/v1/chat/chat', { userId, message });
  },

  security(method, data) {
    switch (method) {
      case 'types':
        return instance.get('/api/v1/security/type');
      case 'create-type':
        return instance.post('/api/v1/security/type', data);
      case 'update-type':
        return instance.put('/api/v1/security/type', data);
      case 'delete-type':
        return instance.delete('/api/v1/security/type', { data: { id: data.id } });
      case 'menus':
        return instance.get('/api/v1/security/menu');
      case 'create-menu':
        return instance.post('/api/v1/security/menu', data);
      case 'update-menu':
        return instance.put('/api/v1/security/menu', data);
      case 'delete-menu':
        return instance.delete('/api/v1/security/menu', { data: { id: data.id } });
      case 'groups':
        return instance.get('/api/v1/security/group');
      case 'create-group':
        return instance.post('/api/v1/security/group', data);
      case 'update-group':
        return instance.put('/api/v1/security/group', data);
      case 'delete-group':
        return instance.delete('/api/v1/security/group', { data: { id: data.id } });
      case 'permissions':
        return instance.get('/api/v1/security/permission');
      case 'my-permissions':
        return instance.get('/api/v1/security/permission/my', { params: data || {} });
      case 'create-permission':
        return instance.post('/api/v1/security/permission', data);
      case 'update-permission':
        return instance.put('/api/v1/security/permission', data);
      case 'create-permission-batch':
        return instance.post('/api/v1/security/permission/create/batch', data);
      case 'update-permission-batch':
        return instance.put('/api/v1/security/permission/update/batch', data);
      case 'delete-permission':
        return instance.delete('/api/v1/security/permission', { data: { id: data.id } });
      case 'assignments':
        return instance.get('/api/v1/security/assignment', { params: data || {} });
      case 'create-assignment':
        return instance.post('/api/v1/security/assignment', data);
      case 'update-assignment':
        return instance.put('/api/v1/security/assignment', data);
      case 'delete-assignment':
        return instance.delete('/api/v1/security/assignment', { data: { id: data.id } });
      case 'audit-events':
        return instance.get('/api/v1/security/audit/events', { params: data || {} });
      default:
        break;
    }
  },

  newSystemDocuments(method, data) {
    switch (method) {
      case 'stats':
        return instance.get('/api/v1/newsystem/documents/stats', { params: data || {} });
      case 'list':
        return instance.get('/api/v1/newsystem/documents', { params: data || {} });
      case 'create':
        return instance.post('/api/v1/newsystem/documents', data || {});
      case 'update':
        return instance.put(`/api/v1/newsystem/documents/${data && (data.id || data._id)}`, data || {});
      case 'delete':
        return instance.delete(`/api/v1/newsystem/documents/${data && (data.id || data._id)}`);
      case 'seed-demo':
        return instance.post('/api/v1/newsystem/documents/seed-demo', data || {});
      default:
        break;
    }
  },

  settings(method, data) {
    switch (method) {
      case 'groups':
        return instance.get('/api/v1/setting/groups', { params: data || {} });
      case 'create-group':
        return instance.post('/api/v1/setting/groups', data);
      case 'update-group':
        return instance.put('/api/v1/setting/groups', data);
      case 'delete-group':
        return instance.delete('/api/v1/setting/groups', { data: { id: data.id || data._id } });
      case 'status':
        return instance.get('/api/v1/setting/status', { params: data || {} });
      case 'create-status':
        return instance.post('/api/v1/setting/status', data);
      case 'update-status':
        return instance.put('/api/v1/setting/status', data);
      case 'delete-status':
        return instance.delete('/api/v1/setting/status', { data: { id: data.id || data._id } });
      case 'messages':
        return instance.get('/api/v1/setting/message', { params: data || {} });
      case 'create-setting-message':
        return instance.post('/api/v1/setting/message', data);
      case 'update-setting-message':
        return instance.put('/api/v1/setting/message', data);
      case 'delete-setting-message':
        return instance.delete('/api/v1/setting/message', { data: { id: data.id || data._id } });
      case 'verification':
        return instance.get('/api/v1/setting/verification', { params: data || {} });
      case 'create-verification':
        return instance.post('/api/v1/setting/verification', data);
      case 'update-verification':
        return instance.put('/api/v1/setting/verification', data);
      case 'delete-verification':
        return instance.delete('/api/v1/setting/verification', { data: { id: data.id || data._id } });
      case 'email-notifications':
        return instance.get('/api/v1/setting/email-notifications', { params: data || {} });
      case 'update-email-notifications':
        return instance.put('/api/v1/setting/email-notifications', data || {});
      case 'email-delivery':
        return instance.get('/api/v1/setting/email-delivery', { params: data || {} });
      case 'update-email-delivery':
        return instance.put('/api/v1/setting/email-delivery', data || {});
      case 'email-workflow-definitions':
        return instance.get('/api/v1/setting/email-workflows/definitions', { params: data || {} });
      case 'email-workflows':
        return instance.get('/api/v1/setting/email-workflows', { params: data || {} });
      case 'create-email-workflow':
        return instance.post('/api/v1/setting/email-workflows', data || {});
      case 'update-email-workflow':
        return instance.put('/api/v1/setting/email-workflows', data || {});
      case 'delete-email-workflow':
        return instance.delete('/api/v1/setting/email-workflows', { data: data || {} });
      case 'runtime-access':
        return instance.get('/api/v1/setting/runtime-access', { params: data || {} });
      case 'update-runtime-access':
        return instance.put('/api/v1/setting/runtime-access', data || {});
      case 'unblock-runtime-access-ip':
        return instance.delete('/api/v1/setting/runtime-access/blocked-ip', { data: data || {} });
      case 'database-backup':
        return instance.get('/api/v1/setting/database-backup', { params: data || {} });
      case 'database-backup-collections':
        return instance.get('/api/v1/setting/database-backup/collections', { params: data || {} });
      case 'update-database-backup':
        return instance.put('/api/v1/setting/database-backup', data || {});
      case 'run-database-backup':
        return instance.post('/api/v1/setting/database-backup/run', data || {});
      case 'delete-database-backup':
        return instance.delete(`/api/v1/setting/database-backup/${(data && (data.id || data._id)) || ''}`);
      case 'download-database-backup':
        return instance.get(`/api/v1/setting/database-backup/${(data && (data.id || data._id)) || ''}/download`, { responseType: 'blob' });
      case 'preview-database-backup':
        return instance.get(`/api/v1/setting/database-backup/${(data && (data.id || data._id)) || ''}/preview`, { params: data || {} });
      case 'restore-database-backup':
        return instance.post(`/api/v1/setting/database-backup/${(data && (data.id || data._id)) || ''}/restore`, data || {});
      case 'lifecycle-options':
        return instance.get('/api/v1/setting/lifecycle/options', { params: data || {} });
      case 'lifecycle-affiliation-types':
        return instance.get('/api/v1/setting/lifecycle/affiliation-types', { params: data || {} });
      case 'create-lifecycle-affiliation-type':
        return instance.post('/api/v1/setting/lifecycle/affiliation-types', data);
      case 'update-lifecycle-affiliation-type':
        return instance.put('/api/v1/setting/lifecycle/affiliation-types', data);
      case 'delete-lifecycle-affiliation-type':
        return instance.delete('/api/v1/setting/lifecycle/affiliation-types', { data: { id: data.id || data._id } });
      case 'lifecycle-access-profiles':
        return instance.get('/api/v1/setting/lifecycle/access-profiles', { params: data || {} });
      case 'create-lifecycle-access-profile':
        return instance.post('/api/v1/setting/lifecycle/access-profiles', data);
      case 'update-lifecycle-access-profile':
        return instance.put('/api/v1/setting/lifecycle/access-profiles', data);
      case 'delete-lifecycle-access-profile':
        return instance.delete('/api/v1/setting/lifecycle/access-profiles', { data: { id: data.id || data._id } });
      case 'lifecycle-position-rules':
        return instance.get('/api/v1/setting/lifecycle/position-rules', { params: data || {} });
      case 'create-lifecycle-position-rule':
        return instance.post('/api/v1/setting/lifecycle/position-rules', data);
      case 'update-lifecycle-position-rule':
        return instance.put('/api/v1/setting/lifecycle/position-rules', data);
      case 'delete-lifecycle-position-rule':
        return instance.delete('/api/v1/setting/lifecycle/position-rules', { data: { id: data.id || data._id } });
      case 'lifecycle-provisioning-policies':
        return instance.get('/api/v1/setting/lifecycle/provisioning-policies', { params: data || {} });
      case 'create-lifecycle-provisioning-policy':
        return instance.post('/api/v1/setting/lifecycle/provisioning-policies', data);
      case 'update-lifecycle-provisioning-policy':
        return instance.put('/api/v1/setting/lifecycle/provisioning-policies', data);
      case 'delete-lifecycle-provisioning-policy':
        return instance.delete('/api/v1/setting/lifecycle/provisioning-policies', { data: { id: data.id || data._id } });
      case 'hr-overview':
        return instance.get('/api/v1/setting/hr/overview', { params: data || {} });
      case 'hr-org-groups':
        return instance.get('/api/v1/setting/hr/org-groups', { params: data || {} });
      case 'create-hr-org-group':
        return instance.post('/api/v1/setting/hr/org-groups', data || {});
      case 'update-hr-org-group':
        return instance.put('/api/v1/setting/hr/org-groups', data || {});
      case 'delete-hr-org-group':
        return instance.delete('/api/v1/setting/hr/org-groups', { data: data || {} });
      case 'hr-org-unit-masters':
        return instance.get('/api/v1/setting/hr/org-unit-masters', { params: data || {} });
      case 'create-hr-org-unit-master':
        return instance.post('/api/v1/setting/hr/org-unit-masters', data || {});
      case 'update-hr-org-unit-master':
        return instance.put('/api/v1/setting/hr/org-unit-masters', data || {});
      case 'delete-hr-org-unit-master':
        return instance.delete('/api/v1/setting/hr/org-unit-masters', { data: data || {} });
      case 'hr-sub-units':
        return instance.get('/api/v1/setting/hr/sub-units', { params: data || {} });
      case 'create-hr-sub-unit':
        return instance.post('/api/v1/setting/hr/sub-units', data || {});
      case 'update-hr-sub-unit':
        return instance.put('/api/v1/setting/hr/sub-units', data || {});
      case 'delete-hr-sub-unit':
        return instance.delete('/api/v1/setting/hr/sub-units', { data: data || {} });
      case 'hr-degree-levels':
        return instance.get('/api/v1/setting/hr/degree-levels', { params: data || {} });
      case 'create-hr-degree-level':
        return instance.post('/api/v1/setting/hr/degree-levels', data || {});
      case 'update-hr-degree-level':
        return instance.put('/api/v1/setting/hr/degree-levels', data || {});
      case 'delete-hr-degree-level':
        return instance.delete('/api/v1/setting/hr/degree-levels', { data: data || {} });
      case 'hr-employment-statuses':
        return instance.get('/api/v1/setting/hr/employment-statuses', { params: data || {} });
      case 'create-hr-employment-status':
        return instance.post('/api/v1/setting/hr/employment-statuses', data || {});
      case 'update-hr-employment-status':
        return instance.put('/api/v1/setting/hr/employment-statuses', data || {});
      case 'delete-hr-employment-status':
        return instance.delete('/api/v1/setting/hr/employment-statuses', { data: data || {} });
      case 'hr-work-lines':
        return instance.get('/api/v1/setting/hr/work-lines', { params: data || {} });
      case 'create-hr-work-line':
        return instance.post('/api/v1/setting/hr/work-lines', data || {});
      case 'update-hr-work-line':
        return instance.put('/api/v1/setting/hr/work-lines', data || {});
      case 'delete-hr-work-line':
        return instance.delete('/api/v1/setting/hr/work-lines', { data: data || {} });
      case 'hr-personnel-types':
        return instance.get('/api/v1/setting/hr/personnel-types', { params: data || {} });
      case 'create-hr-personnel-type':
        return instance.post('/api/v1/setting/hr/personnel-types', data || {});
      case 'update-hr-personnel-type':
        return instance.put('/api/v1/setting/hr/personnel-types', data || {});
      case 'delete-hr-personnel-type':
        return instance.delete('/api/v1/setting/hr/personnel-types', { data: data || {} });
      case 'hr-academic-ranks':
        return instance.get('/api/v1/setting/hr/academic-ranks', { params: data || {} });
      case 'create-hr-academic-rank':
        return instance.post('/api/v1/setting/hr/academic-ranks', data || {});
      case 'update-hr-academic-rank':
        return instance.put('/api/v1/setting/hr/academic-ranks', data || {});
      case 'delete-hr-academic-rank':
        return instance.delete('/api/v1/setting/hr/academic-ranks', { data: data || {} });
      case 'hr-position-titles':
        return instance.get('/api/v1/setting/hr/position-titles', { params: data || {} });
      case 'hr-positions':
        return instance.get('/api/v1/setting/hr/positions', { params: data || {} });
      case 'hr-workforce':
        return instance.get('/api/v1/setting/hr/workforce', { params: data || {} });
      case 'hr-identities':
        return instance.get('/api/v1/setting/hr/identities', { params: data || {} });
      case 'link-hr-identity-account':
        return instance.put('/api/v1/setting/hr/identities/link-account', data || {});
      case 'hr-sync-runs':
        return instance.get('/api/v1/setting/hr/sync/runs', { params: data || {} });
      case 'hr-sync-preview':
        return instance.post('/api/v1/setting/hr/sync/preview', data || {});
      case 'hr-sync-run':
        return instance.post('/api/v1/setting/hr/sync/run', data || {});
      case 'create-hr-position-title':
        return instance.post('/api/v1/setting/hr/position-titles', data || {});
      case 'update-hr-position-title':
        return instance.put('/api/v1/setting/hr/position-titles', data || {});
      case 'delete-hr-position-title':
        return instance.delete('/api/v1/setting/hr/position-titles', { data: data || {} });
      case 'work-status-timeline':
        return instance.get('/api/v1/setting/work-status/timeline', { params: data || {} });
      case 'work-status-timeline-one':
        return instance.get('/api/v1/setting/work-status/timeline/one', { params: data || {} });
      case 'create-work-status-timeline':
        return instance.post('/api/v1/setting/work-status/timeline', data);
      case 'update-work-status-timeline':
        return instance.put('/api/v1/setting/work-status/timeline', data);
      case 'delete-work-status-timeline':
        return instance.delete('/api/v1/setting/work-status/timeline', { data: { id: data.id || data._id } });
      case 'work-status-timeline-decision':
        return instance.put('/api/v1/setting/work-status/timeline/decision', data);
      case 'universities':
        return instance.get('/api/v1/setting/universities', { params: data || {} });
      case 'create-university':
        return instance.post('/api/v1/setting/universities', data);
      case 'update-university':
        return instance.put('/api/v1/setting/universities', data);
      case 'delete-university':
        return instance.delete('/api/v1/setting/universities', { data: { id: data.id || data._id } });
      case 'positions':
        return instance.get('/api/v1/setting/positions', { params: data || {} });
      case 'create-position':
        return instance.post('/api/v1/setting/positions', data);
      case 'update-position':
        return instance.put('/api/v1/setting/positions', data);
      case 'delete-position':
        return instance.delete('/api/v1/setting/positions', { data: { id: data.id || data._id } });
      case 'work-status-types':
        return instance.get('/api/v1/setting/work-status-types', { params: data || {} });
      case 'create-work-status-type':
        return instance.post('/api/v1/setting/work-status-types', data);
      case 'update-work-status-type':
        return instance.put('/api/v1/setting/work-status-types', data);
      case 'delete-work-status-type':
        return instance.delete('/api/v1/setting/work-status-types', { data: { id: data.id || data._id } });
      case 'training-courses':
        return instance.get('/api/v1/setting/training-courses', { params: data || {} });
      case 'create-training-course':
        return instance.post('/api/v1/setting/training-courses', data);
      case 'update-training-course':
        return instance.put('/api/v1/setting/training-courses', data);
      case 'delete-training-course':
        return instance.delete('/api/v1/setting/training-courses', { data: { id: data.id || data._id } });
      default:
        break;
    }
  },

  employment(method, data) {
    switch (method) {
      case 'records':
        return instance.get('/api/v1/employment/records', { params: data || {} });
      case 'create-record':
        return instance.post('/api/v1/employment/records', data);
      case 'update-record':
        return instance.put('/api/v1/employment/records', data);
      case 'transfer-record':
        return instance.put('/api/v1/employment/records/transfer', data);
      case 'delete-record':
        return instance.delete('/api/v1/employment/records', { data: { id: data.id || data._id } });
      case 'contracts':
        return instance.get('/api/v1/employment/contracts', { params: data || {} });
      case 'create-contract':
        return instance.post('/api/v1/employment/contracts', data);
      case 'update-contract':
        return instance.put('/api/v1/employment/contracts', data);
      case 'delete-contract':
        return instance.delete('/api/v1/employment/contracts', { data: { id: data.id || data._id } });
      case 'history':
        return instance.get('/api/v1/employment/history', { params: data || {} });
      case 'history-timeline':
        return instance.get('/api/v1/employment/history/timeline', { params: data || {} });
      case 'create-history':
        return instance.post('/api/v1/employment/history', data);
      case 'update-history':
        return instance.put('/api/v1/employment/history', data);
      case 'delete-history':
        return instance.delete('/api/v1/employment/history', { data: { id: data.id || data._id } });
      case 'references':
        return instance.get('/api/v1/employment/references', { params: data || {} });
      case 'create-reference':
        return instance.post('/api/v1/employment/references', data);
      case 'update-reference':
        return instance.put('/api/v1/employment/references', data);
      case 'delete-reference':
        return instance.delete('/api/v1/employment/references', { data: { id: data.id || data._id } });
      case 'organization-groups':
        return instance.get('/api/v1/employment/organization-groups', { params: data || {} });
      case 'create-organization-group':
        return instance.post('/api/v1/employment/organization-groups', data);
      case 'update-organization-group':
        return instance.put('/api/v1/employment/organization-groups', data);
      case 'delete-organization-group':
        return instance.delete('/api/v1/employment/organization-groups', { data: { id: data.id || data._id } });
      case 'organization-units':
        return instance.get('/api/v1/employment/organization-units', { params: data || {} });
      case 'create-organization-unit':
        return instance.post('/api/v1/employment/organization-units', data);
      case 'update-organization-unit':
        return instance.put('/api/v1/employment/organization-units', data);
      case 'delete-organization-unit':
        return instance.delete('/api/v1/employment/organization-units', { data: { id: data.id || data._id } });
      case 'academic-ranks':
        return instance.get('/api/v1/employment/academic-ranks', { params: data || {} });
      case 'create-academic-rank':
        return instance.post('/api/v1/employment/academic-ranks', data);
      case 'update-academic-rank':
        return instance.put('/api/v1/employment/academic-ranks', data);
      case 'delete-academic-rank':
        return instance.delete('/api/v1/employment/academic-ranks', { data: { id: data.id || data._id } });
      case 'work-lines':
        return instance.get('/api/v1/employment/work-lines', { params: data || {} });
      case 'create-work-line':
        return instance.post('/api/v1/employment/work-lines', data);
      case 'update-work-line':
        return instance.put('/api/v1/employment/work-lines', data);
      case 'delete-work-line':
        return instance.delete('/api/v1/employment/work-lines', { data: { id: data.id || data._id } });
      case 'employee-types':
        return instance.get('/api/v1/employment/employee-types', { params: data || {} });
      case 'create-employee-type':
        return instance.post('/api/v1/employment/employee-types', data);
      case 'update-employee-type':
        return instance.put('/api/v1/employment/employee-types', data);
      case 'delete-employee-type':
        return instance.delete('/api/v1/employment/employee-types', { data: { id: data.id || data._id } });
      case 'import-hr-csv':
        return instance.post('/api/v1/employment/import/hr/csv', data);
      case 'import-hr-review':
        return instance.get('/api/v1/employment/import/hr/review', { params: data || {} });
      default:
        break;
    }
  },

  attachments(method, data) {
    switch (method) {
      case 'list':
        return instance.get('/api/v1/attachments', { params: data || {} });
      case 'create':
        return instance.post('/api/v1/attachments', data);
      case 'update':
        return instance.put('/api/v1/attachments', data);
      case 'delete':
        return instance.delete('/api/v1/attachments', { data: { id: data && (data.id || data._id) } });
      default:
        break;
    }
  },

  audit(method, data) {
    switch (method) {
      case 'logs':
        return instance.get('/api/v1/audit/logs', { params: data || {} });
      case 'create-log':
        return instance.post('/api/v1/audit/logs', data);
      case 'update-log':
        return instance.put('/api/v1/audit/logs', data);
      case 'delete-log':
        return instance.delete('/api/v1/audit/logs', { data: { id: data && (data.id || data._id) } });
      default:
        break;
    }
  }
}

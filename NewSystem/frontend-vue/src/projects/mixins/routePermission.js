export default {
  data() {
    return {
      permissionReady: false
    };
  },
  computed: {
    currentPermission() {
      const permission = this.findPermissionByRoute(this.$route.path);
      return permission?.permissions || {
        view: false,
        add: false,
        edit: false,
        delete: false
      };
    },
    canView() {
      return !!this.currentPermission.view;
    },
    canAdd() {
      return !!this.currentPermission.add;
    },
    canEdit() {
      return !!this.currentPermission.edit;
    },
    canDelete() {
      return !!this.currentPermission.delete;
    }
  },
  methods: {
    normalizeRoute(route) {
      const raw = String(route || "").trim();
      if (!raw) return "";
      let normalized = raw;
      const protocolIndex = normalized.indexOf("://");
      if (protocolIndex !== -1) {
        const slashAfterHost = normalized.indexOf("/", protocolIndex + 3);
        normalized = slashAfterHost !== -1 ? normalized.slice(slashAfterHost) : "/";
      }

      const hashIndex = normalized.indexOf("#");
      if (hashIndex !== -1) normalized = normalized.slice(0, hashIndex);
      const queryIndex = normalized.indexOf("?");
      if (queryIndex !== -1) normalized = normalized.slice(0, queryIndex);

      normalized = normalized.replace(/\/{2,}/g, "/");
      if (!normalized.startsWith("/")) normalized = `/${normalized}`;
      if (normalized.length > 1 && normalized.endsWith("/")) {
        normalized = normalized.slice(0, -1);
      }
      return normalized;
    },
    hasDynamicSegment(route) {
      return /\/:[^/]+/.test(route);
    },
    isDynamicLikeSegment(segment) {
      if (!segment) return false;
      if (/^\d+$/.test(segment)) return true; // numeric id like 00/15
      if (/^[0-9a-fA-F]{24}$/.test(segment)) return true; // mongo object id
      if (/^[0-9a-fA-F-]{36}$/.test(segment) && segment.includes("-")) return true; // uuid
      return false;
    },
    stripDynamicTail(route) {
      const normalized = this.normalizeRoute(route);
      if (!normalized || normalized === "/") return normalized;
      const parts = normalized.split("/").filter(Boolean);
      while (parts.length > 0 && this.isDynamicLikeSegment(parts[parts.length - 1])) {
        parts.pop();
      }
      return parts.length ? `/${parts.join("/")}` : "/";
    },
    matchRoute(targetRoute, permissionRoute) {
      if (!targetRoute || !permissionRoute) return false;
      if (targetRoute === permissionRoute) return true;
      if (this.hasDynamicSegment(permissionRoute)) {
        const escaped = permissionRoute.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
        const pattern = escaped.replace(/\\\/:[^/]+/g, "/[^/]+");
        const matcher = new RegExp(`^${pattern}$`);
        if (matcher.test(targetRoute)) return true;
      }

      // Fallback for routes that carry changing trailing ids, e.g. /management/product/routing/00/15
      // and permission is saved as a base route like /management/product/routing.
      const targetBase = this.stripDynamicTail(targetRoute);
      const permissionBase = this.stripDynamicTail(permissionRoute);
      return !!targetBase && !!permissionBase && targetBase === permissionBase;
    },
    getCurrentRoleId() {
      const role = this.$store.getters["auth/role"];
      if (!role) return null;
      if (typeof role === "object") {
        return role.id || role._id || null;
      }
      return role;
    },
    loadPermissionForCurrentRole() {
      const roleId = this.getCurrentRoleId();
      if (!roleId) {
        this.permissionReady = true;
        return Promise.resolve();
      }
      this.permissionReady = false;
      return this.$store.dispatch("authorization/permission/config", { role: roleId })
        .finally(() => {
          this.permissionReady = true;
        });
    },
    findPermissionByRoute(routePath) {
      const currentRoute = this.normalizeRoute(routePath);
      const roleId = this.getCurrentRoleId();
      if (!currentRoute || !roleId) return null;

      const permissions = this.$store.getters["authorization/permission/item"] || [];
      return permissions.find((perm) => {
        const permRoleId = typeof perm.role === "object"
          ? (perm.role.id || perm.role._id)
          : (perm.role_id || perm.role);
        const permRouteRaw = typeof perm.menu === "object"
          ? perm.menu.route
          : (perm.menu_route || "");
        const permRoute = this.normalizeRoute(permRouteRaw);
        return String(permRoleId) === String(roleId) && this.matchRoute(currentRoute, permRoute);
      }) || null;
    },
    notifyPermissionDenied(actionKey) {
      this.$store.commit("dialog/toasts", [{
        message: this.$t(actionKey),
        color: "warning"
      }]);
    }
  }
};

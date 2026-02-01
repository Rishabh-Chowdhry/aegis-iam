import { Router } from "express";
import { PermissionController } from "./controller";
import { PermissionGuard } from "./guard";

const router = Router();
const permissionController = new PermissionController(null as any); // Will be injected
const permissionGuard = new PermissionGuard();

// Routes
router.post(
  "/",
  permissionGuard.checkPermission("permissions", "create"),
  permissionController.createPermission.bind(permissionController),
);

router.put(
  "/:permissionId",
  permissionGuard.checkPermission("permissions", "update"),
  permissionController.updatePermission.bind(permissionController),
);

router.delete(
  "/:permissionId",
  permissionGuard.checkPermission("permissions", "delete"),
  permissionController.deletePermission.bind(permissionController),
);

router.get(
  "/:permissionId",
  permissionGuard.checkPermission("permissions", "read"),
  permissionController.getPermission.bind(permissionController),
);

router.get(
  "/",
  permissionGuard.checkPermission("permissions", "read"),
  permissionController.getAllPermissions.bind(permissionController),
);

router.get(
  "/check/:resource/:action",
  permissionGuard.checkPermission("permissions", "read"),
  permissionController.checkPermission.bind(permissionController),
);

export { router as permissionRoutes };

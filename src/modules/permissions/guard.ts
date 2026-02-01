import { Request, Response, NextFunction } from "express";
import { PermissionService } from "./service";

export class PermissionGuard {
  constructor(private permissionService?: PermissionService) {}

  checkPermission(resource: string, action: string) {
    return async (req: Request, res: Response, next: NextFunction) => {
      if (!this.permissionService) {
        return res
          .status(500)
          .json({ error: "Permission service not initialized" });
      }

      try {
        const hasPermission = await this.permissionService.checkPermission(
          resource,
          action,
          req.tenantId || "default",
        );

        if (!hasPermission) {
          return res.status(403).json({ error: "Insufficient permissions" });
        }

        next();
      } catch (error) {
        // Fail-closed: deny access on error
        console.error("Permission check failed:", error);
        res.status(403).json({ error: "Permission check failed" });
      }
    };
  }
}

import { Request, Response } from "express";
import { PermissionService } from "./service";
import {
  CreatePermissionSchema,
  UpdatePermissionSchema,
  GetPermissionSchema,
} from "./schemas";
import { StatusMapping } from "../../shared/errors/StatusMapping";
import { ResponseStatus } from "../../shared/errors/ResponseStatus";

export class PermissionController {
  constructor(private permissionService: PermissionService) {}

  async createPermission(req: Request, res: Response) {
    try {
      const validatedData = CreatePermissionSchema.parse(req.body);
      const result = await this.permissionService.createPermission({
        ...validatedData,
        performedBy: req.user?.id || "system",
      });
      res
        .status(ResponseStatus.CREATED)
        .json(StatusMapping.createResponse(ResponseStatus.CREATED, result));
    } catch (error) {
      res
        .status(ResponseStatus.BAD_REQUEST)
        .json(
          StatusMapping.createErrorResponse(
            ResponseStatus.BAD_REQUEST,
            error instanceof Error ? error.message : "Unknown error",
          ),
        );
    }
  }

  async updatePermission(req: Request, res: Response) {
    try {
      const { permissionId } = req.params;
      const validatedData = UpdatePermissionSchema.parse(req.body);
      const result = await this.permissionService.updatePermission({
        id: permissionId,
        ...validatedData,
        tenantId: req.tenantId,
        performedBy: req.user?.id || "system",
      });
      res
        .status(ResponseStatus.OK)
        .json(StatusMapping.createResponse(ResponseStatus.OK, result));
    } catch (error) {
      console.log("Error in createPermission:", error);
      res
        .status(ResponseStatus.BAD_REQUEST)
        .json(
          StatusMapping.createErrorResponse(
            ResponseStatus.BAD_REQUEST,
            (error as Error).message,
          ),
        );
    }
  }

  async deletePermission(req: Request, res: Response) {
    try {
      const { permissionId } = req.params;
      await this.permissionService.deletePermission({
        id: permissionId,
        tenantId: req.tenantId,
        performedBy: req.user?.id || "system",
      });
      res.status(ResponseStatus.NO_CONTENT).send();
    } catch (error) {
      res
        .status(ResponseStatus.BAD_REQUEST)
        .json(
          StatusMapping.createErrorResponse(
            ResponseStatus.BAD_REQUEST,
            error instanceof Error ? error.message : "Unknown error",
          ),
        );
    }
  }

  async getPermission(req: Request, res: Response) {
    try {
      const { permissionId } = req.params;
      const permission = await this.permissionService.getPermission({
        id: permissionId,
        tenantId: req.tenantId,
      });
      if (!permission) {
        return res
          .status(ResponseStatus.NOT_FOUND)
          .json(
            StatusMapping.createErrorResponse(
              ResponseStatus.NOT_FOUND,
              "Permission not found",
            ),
          );
      }
      res
        .status(ResponseStatus.OK)
        .json(StatusMapping.createResponse(ResponseStatus.OK, { permission }));
    } catch (error) {
      res
        .status(ResponseStatus.BAD_REQUEST)
        .json(
          StatusMapping.createErrorResponse(
            ResponseStatus.BAD_REQUEST,
            error instanceof Error ? error.message : "Unknown error",
          ),
        );
    }
  }

  async getAllPermissions(req: Request, res: Response) {
    try {
      const validatedData = GetPermissionSchema.parse(req.query);
      const permissions =
        await this.permissionService.getAllPermissions(validatedData);
      res
        .status(ResponseStatus.OK)
        .json(StatusMapping.createResponse(ResponseStatus.OK, { permissions }));
    } catch (error) {
      res
        .status(ResponseStatus.BAD_REQUEST)
        .json(
          StatusMapping.createErrorResponse(
            ResponseStatus.BAD_REQUEST,
            error instanceof Error ? error.message : "Unknown error",
          ),
        );
    }
  }

  async checkPermission(req: Request, res: Response) {
    try {
      const { resource, action } = req.params;
      const hasPermission = await this.permissionService.checkPermission(
        resource,
        action,
        req.tenantId || "",
      );
      res
        .status(ResponseStatus.OK)
        .json(
          StatusMapping.createResponse(ResponseStatus.OK, { hasPermission }),
        );
    } catch (error) {
      res
        .status(ResponseStatus.BAD_REQUEST)
        .json(
          StatusMapping.createErrorResponse(
            ResponseStatus.BAD_REQUEST,
            error instanceof Error ? error.message : "Unknown error",
          ),
        );
    }
  }
}

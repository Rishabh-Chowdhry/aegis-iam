import { Request, Response } from "express";
import { RoleService } from "./service";
import {
  CreateRoleSchema,
  UpdateRoleSchema,
  AssignPermissionSchema,
  RemovePermissionSchema,
  GetRoleHierarchySchema,
} from "./schemas";
import { StatusMapping } from "../../shared/errors/StatusMapping";
import { ResponseStatus } from "../../shared/errors/ResponseStatus";

export class RoleController {
  constructor(private roleService: RoleService) {}

  async createRole(req: Request, res: Response) {
    try {
      const validatedData = CreateRoleSchema.parse(req.body);
      const result = await this.roleService.createRole({
        ...validatedData,
        performedBy: req.user?.id || "system", // Assuming auth middleware sets req.user
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

  async updateRole(req: Request, res: Response) {
    try {
      const { roleId } = req.params;
      const validatedData = UpdateRoleSchema.parse(req.body);
      const result = await this.roleService.updateRole({
        roleId,
        ...validatedData,
        tenantId: req.tenantId || "default",
        performedBy: req.user?.id || "system",
      } as any);
      res
        .status(ResponseStatus.OK)
        .json(StatusMapping.createResponse(ResponseStatus.OK, result));
    } catch (error) {
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

  async deleteRole(req: Request, res: Response) {
    try {
      const { roleId } = req.params;
      const result = await this.roleService.deleteRole({
        roleId,
        tenantId: req.tenantId || "default",
        performedBy: req.user?.id || "system",
      });
      res
        .status(ResponseStatus.OK)
        .json(StatusMapping.createResponse(ResponseStatus.OK, result));
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

  async getRole(req: Request, res: Response) {
    try {
      const { roleId } = req.params;
      const role = await this.roleService.getRoleById(
        roleId,
        req.tenantId || "default",
      );
      if (!role) {
        return res
          .status(ResponseStatus.NOT_FOUND)
          .json(
            StatusMapping.createErrorResponse(
              ResponseStatus.NOT_FOUND,
              "Role not found",
            ),
          );
      }
      res
        .status(ResponseStatus.OK)
        .json(StatusMapping.createResponse(ResponseStatus.OK, { role }));
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

  async getAllRoles(req: Request, res: Response) {
    try {
      const tenantId = req.tenantId || "default";
      const roles = await this.roleService.getAllRoles(tenantId);
      res
        .status(ResponseStatus.OK)
        .json(StatusMapping.createResponse(ResponseStatus.OK, { roles }));
    } catch (error) {
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

  async assignPermission(req: Request, res: Response) {
    try {
      const { roleId } = req.params;
      const validatedData = AssignPermissionSchema.parse(req.body);
      const result = await this.roleService.assignPermissionToRole({
        roleId,
        ...validatedData,
        tenantId: req.tenantId || "default",
        performedBy: req.user?.id || "system",
      });
      res
        .status(ResponseStatus.OK)
        .json(StatusMapping.createResponse(ResponseStatus.OK, result));
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

  async removePermission(req: Request, res: Response) {
    try {
      const { roleId } = req.params;
      const validatedData = RemovePermissionSchema.parse(req.body);
      const result = await this.roleService.removePermissionFromRole({
        roleId,
        ...validatedData,
        tenantId: req.tenantId || "default",
        performedBy: req.user?.id || "system",
      });
      res
        .status(ResponseStatus.OK)
        .json(StatusMapping.createResponse(ResponseStatus.OK, result));
    } catch (error) {
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

  async getRoleHierarchy(req: Request, res: Response) {
    try {
      const validatedData = GetRoleHierarchySchema.parse(req.query);
      const result = await this.roleService.getRoleHierarchy(validatedData);
      res
        .status(ResponseStatus.OK)
        .json(StatusMapping.createResponse(ResponseStatus.OK, result));
    } catch (error) {
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

  async checkPermission(req: Request, res: Response) {
    try {
      const { roleId, permissionId } = req.params;
      const hasPermission = await this.roleService.checkPermission(
        roleId,
        permissionId,
        req.tenantId || "default",
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
            (error as Error).message,
          ),
        );
    }
  }
}

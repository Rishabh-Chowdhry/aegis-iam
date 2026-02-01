import { Role } from "../../domain/entities/Role";
import { IRoleRepository } from "../../infrastructure/repositories/IRoleRepository";

export interface RoleHierarchyNode {
  role: Role;
  children: RoleHierarchyNode[];
}

export interface GetRoleHierarchyRequest {
  tenantId: string;
}

export interface GetRoleHierarchyResponse {
  hierarchy: RoleHierarchyNode[];
}

export class GetRoleHierarchyUseCase {
  constructor(private roleRepository: IRoleRepository) {}

  async execute(
    request: GetRoleHierarchyRequest,
  ): Promise<GetRoleHierarchyResponse> {
    const { tenantId } = request;

    const allRoles = await this.roleRepository.findAll(tenantId);
    const roleMap = new Map<string, Role>();
    allRoles.forEach((role) => roleMap.set(role.id, role));

    const rootRoles = allRoles.filter((role) => !role.parentId);
    const hierarchy = rootRoles.map((root) =>
      this.buildHierarchy(root, roleMap),
    );

    return { hierarchy };
  }

  private buildHierarchy(
    role: Role,
    roleMap: Map<string, Role>,
  ): RoleHierarchyNode {
    const children = Array.from(roleMap.values())
      .filter((r) => r.parentId === role.id)
      .map((child) => this.buildHierarchy(child, roleMap));

    return {
      role,
      children,
    };
  }
}

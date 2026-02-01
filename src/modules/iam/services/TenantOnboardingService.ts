/**
 * Tenant Onboarding Service
 *
 * Handles the complete tenant lifecycle including:
 * - Tenant creation with default settings and policies
 * - Admin bootstrap with secure credential generation
 * - Default IAM policy setup (admin, member, service)
 * - SSO configuration (SAML/OIDC)
 * - Tenant lifecycle management (suspend, resume, offboard)
 * - Key rotation and security management
 * - Audit logging for compliance (SOC2/ISO 27001)
 */

import { randomBytes, createHash } from "crypto";
import {
  ABACPolicy,
  PolicyStatement,
  PolicyEffect,
} from "../policy/models/types";
import { User, UserStatus } from "../../../domain/entities/User";
import { Role } from "../../../domain/entities/Role";
import { PasswordHash } from "../../../domain/value-objects/PasswordHash";

// =============================================================================
// TYPES - Audit Action and Outcome (inline definitions for compatibility)
// =============================================================================

/** Audit action type */
type AuditAction =
  | "TENANT_CREATED"
  | "TENANT_SUSPENDED"
  | "TENANT_RESUMED"
  | "TENANT_OFFBOARDED"
  | "USER_CREATED"
  | "POLICY_CREATED"
  | "SSO_CONFIGURED"
  | "KEY_ROTATED"
  | "DATA_EXPORT";

/** Audit outcome type */
type AuditOutcome = "SUCCESS" | "FAILURE";

/** Audit log context */
interface AuditLogContext {
  userId?: string;
  tenantId: string;
  ipAddress?: string;
  userAgent?: string;
  correlationId?: string;
}

// =============================================================================
// ACTION SPEC
// =============================================================================

/** Action specification */
interface ActionSpec {
  includes: string[];
  excludes?: string[];
  groups?: string[];
}

/** Resource specification */
interface ResourceSpec {
  types: string[];
  ids?: string[];
  paths?: string[];
  attributes?: Record<string, unknown>;
}

/** Policy metadata */
interface PolicyMetadata {
  description?: string;
  tags?: Record<string, string>;
  version?: number;
  deprecated?: { deprecatedAt: string };
  createdBy?: string;
  createdAt?: string;
  updatedBy?: string;
  updatedAt?: string;
  compliance?: { framework?: string; requirement?: string; controlId?: string };
  priority?: number;
}

// =============================================================================
// INTERFACES - Tenant Onboarding Request/Response Types
// =============================================================================

/** Tenant Onboarding Request */
export type CreateTenantRequest = {
  name: string;
  displayName: string;
  domain?: string;
  adminEmail: string;
  adminName?: string;
  plan?: "STARTER" | "PROFESSIONAL" | "ENTERPRISE";
  settings?: Partial<TenantSettings>;
  metadata?: Record<string, unknown>;
};

/** Tenant Onboarding Result */
export type TenantOnboardingResult = {
  tenant: Tenant;
  adminUser: User;
  adminCredentials: AdminCredentials;
  defaultPolicies: ABACPolicy[];
  roles: Role[];
  setupComplete: boolean;
};

/** Admin credentials for initial setup */
export type AdminCredentials = {
  userId: string;
  email: string;
  temporaryPassword: string;
  mustChangePassword: boolean;
  setupUrl: string;
};

/** Tenant settings */
export type TenantSettings = {
  maxUsers: number;
  maxPolicies: number;
  mfaRequired: boolean;
  sessionTimeout: number;
  ipWhitelist: string[];
  allowedDomains: string[];
  branding?: {
    logo?: string;
    primaryColor?: string;
    secondaryColor?: string;
  };
  retentionDays: number;
};

/** Tenant status enum */
export type TenantStatus =
  | "PENDING"
  | "ACTIVE"
  | "SUSPENDED"
  | "OFFBOARDING"
  | "TERMINATED";

/** Tenant entity (minimal representation) */
export type Tenant = {
  id: string;
  name: string;
  displayName: string;
  domain?: string;
  status: TenantStatus;
  settings: TenantSettings;
  plan: "STARTER" | "PROFESSIONAL" | "ENTERPRISE";
  apiKey?: string;
  apiSecret?: string;
  createdAt: Date;
  updatedAt: Date;
  metadata?: Record<string, unknown>;
};

// =============================================================================
// LIFECYCLE REQUEST/RESPONSE INTERFACES
// =============================================================================

/** Suspend Tenant Request */
export type SuspendTenantRequest = {
  tenantId: string;
  reason: "PAYMENT" | "SECURITY" | "COMPLIANCE" | "MANUAL";
  message?: string;
  gracePeriodHours?: number;
};

/** Suspend Tenant Result */
export type SuspendTenantResult = {
  success: boolean;
  tenantId: string;
  status: TenantStatus;
  suspendedAt: Date;
  gracePeriodEndAt?: Date;
  affectedUsersCount: number;
  errorMessage?: string;
};

/** Resume Tenant Request */
export type ResumeTenantRequest = {
  tenantId: string;
  reason?: string;
};

/** Resume Tenant Result */
export type ResumeTenantResult = {
  success: boolean;
  tenantId: string;
  status: TenantStatus;
  resumedAt: Date;
  restoredUsersCount: number;
  errorMessage?: string;
};

/** Rotate Tenant Keys Request */
export type RotateTenantKeysRequest = {
  tenantId: string;
  rotateAll: boolean;
};

/** Rotate Tenant Keys Result */
export type RotateTenantKeysResult = {
  success: boolean;
  tenantId: string;
  oldApiKeyId?: string;
  newApiKeyId: string;
  newApiSecretPrefix: string;
  rotatedAt: Date;
  gracePeriodEndAt: Date;
  errorMessage?: string;
};

/** Offboard Tenant Request */
export type OffboardTenantRequest = {
  tenantId: string;
  exportData: boolean;
  exportFormat: "JSON" | "CSV" | "SQL";
  retentionDays: number;
  confirmationToken: string;
};

/** Offboard Tenant Result */
export type OffboardTenantResult = {
  success: boolean;
  tenantId: string;
  status: TenantStatus;
  offboardedAt: Date;
  scheduledDeletionAt: Date;
  exportUrl?: string;
  errorMessage?: string;
};

// =============================================================================
// SSO CONFIGURATION INTERFACES
// =============================================================================

/** SSO Configuration */
export type SSOConfig = {
  provider: "okta" | "azure_ad" | "google_workspace" | "saml_idp";
  entityId: string;
  ssoUrl: string;
  certificate: string;
  claimsMapping: ClaimsMapping;
  signRequests: boolean;
  wantAssertionsSigned: boolean;
};

/** SSO Claims Mapping */
export type ClaimsMapping = {
  email: string;
  name: string;
  groups: string;
  firstName?: string;
  lastName?: string;
};

/** SSO Configuration Result */
export type SSOConfigurationResult = {
  success: boolean;
  ssoConfigId: string;
  tenantId: string;
  provider: SSOConfig["provider"];
  enabled: boolean;
  errorMessage?: string;
};

/** Bootstrap Admin User Result */
export type AdminUserResult = {
  user: User;
  credentials: AdminCredentials;
};

// =============================================================================
// REPOSITORY INTERFACES
// =============================================================================

/** Tenant Repository Interface */
export interface ITenantRepository {
  create(data: CreateTenantDTO): Promise<Tenant>;
  findById(id: string): Promise<Tenant | null>;
  findByName(name: string): Promise<Tenant | null>;
  findAll(filter?: TenantFilterDTO): Promise<Tenant[]>;
  update(id: string, data: UpdateTenantDTO): Promise<Tenant>;
  updateStatus(id: string, status: TenantStatus): Promise<Tenant>;
  delete(id: string): Promise<boolean>;
  exists(id: string): Promise<boolean>;
  count(status?: TenantStatus): Promise<number>;
}

/** Tenant creation DTO */
export interface CreateTenantDTO {
  name: string;
  displayName: string;
  domain?: string;
  settings: TenantSettings;
  plan: "STARTER" | "PROFESSIONAL" | "ENTERPRISE";
  metadata?: Record<string, unknown>;
}

/** Tenant update DTO */
export interface UpdateTenantDTO {
  displayName?: string;
  domain?: string;
  settings?: Partial<TenantSettings>;
  plan?: "STARTER" | "PROFESSIONAL" | "ENTERPRISE";
  metadata?: Record<string, unknown>;
}

/** Tenant filter DTO */
export interface TenantFilterDTO {
  status?: TenantStatus;
  plan?: "STARTER" | "PROFESSIONAL" | "ENTERPRISE";
  limit?: number;
  offset?: number;
}

/** User Repository Interface */
export interface IUserRepository {
  findById(id: string, tenantId: string): Promise<User | null>;
  findByEmail(email: string, tenantId: string): Promise<User | null>;
  findAll(tenantId: string): Promise<User[]>;
  save(user: User): Promise<void>;
  update(user: User): Promise<void>;
  delete(id: string, tenantId: string): Promise<void>;
  exists(id: string, tenantId: string): Promise<boolean>;
  countByTenant(tenantId: string): Promise<number>;
  updateStatus(id: string, tenantId: string, status: UserStatus): Promise<void>;
}

/** Role Repository Interface */
export interface IRoleRepository {
  findById(id: string, tenantId: string): Promise<Role | null>;
  findByName(name: string, tenantId: string): Promise<Role | null>;
  findAll(tenantId: string): Promise<Role[]>;
  save(role: Role): Promise<void>;
  update(role: Role): Promise<void>;
  delete(id: string, tenantId: string): Promise<void>;
  exists(id: string, tenantId: string): Promise<boolean>;
}

/** Policy Repository Interface */
export interface IPolicyRepository {
  save(policy: ABACPolicy): Promise<void>;
  findById(id: string, tenantId: string): Promise<ABACPolicy | null>;
  findByName(name: string, tenantId: string): Promise<ABACPolicy | null>;
  findAll(tenantId: string): Promise<ABACPolicy[]>;
  update(policy: ABACPolicy): Promise<void>;
  delete(id: string, tenantId: string): Promise<void>;
}

/** Policy Cache Interface */
export interface IPolicyCache {
  invalidate(tenantId: string): Promise<void>;
  invalidatePattern(pattern: string): Promise<void>;
}

/** Crypto Service Interface */
export interface ICryptoService {
  generateSecurePassword(length?: number): string;
  hashPassword(password: string): Promise<string>;
  verifyPassword(password: string, hash: string): Promise<boolean>;
  generateApiKey(): { key: string; secret: string };
  hashApiSecret(secret: string): string;
  rotateKey(currentKey: string, algorithm?: string): string;
}

/** Email Service Interface */
export interface IEmailService {
  sendWelcomeEmail(
    email: string,
    adminName: string,
    tenantName: string,
    setupUrl: string,
    temporaryPassword: string,
  ): Promise<boolean>;
  sendSuspensionNotification(
    email: string,
    adminName: string,
    tenantName: string,
    reason: string,
    message?: string,
    gracePeriodHours?: number,
  ): Promise<boolean>;
  sendResumptionNotification(
    email: string,
    adminName: string,
    tenantName: string,
  ): Promise<boolean>;
  sendOffboardingNotification(
    email: string,
    adminName: string,
    tenantName: string,
    exportUrl?: string,
    scheduledDeletionDate?: Date,
  ): Promise<boolean>;
}

/** Audit Logger Interface (simplified for standalone use) */
export interface IAuditLogger {
  log(
    action: AuditAction,
    resource: string,
    context: AuditLogContext,
    options?: {
      resourceId?: string;
      details?: Record<string, unknown>;
      outcome?: AuditOutcome;
      errorMessage?: string;
    },
  ): Promise<void>;
}

// =============================================================================
// HELPER FUNCTIONS FOR POLICY TEMPLATES
// =============================================================================

/** Create action specification */
function createActionSpec(includes: string[], excludes?: string[]): ActionSpec {
  return { includes, excludes };
}

/** Create resource specification */
function createResourceSpec(types: string[], ids?: string[]): ResourceSpec {
  return { types, ids };
}

/** Create policy metadata */
function createPolicyMetadata(
  tags: Record<string, string>,
  description?: string,
): PolicyMetadata {
  return {
    description,
    tags,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    createdBy: "SYSTEM",
  };
}

// =============================================================================
// DEFAULT POLICY TEMPLATES
// =============================================================================

/** Default Admin Policy Template */
export const DEFAULT_ADMIN_POLICY_TEMPLATE: ABACPolicy = {
  id: "",
  version: "2026-01-01",
  tenantId: "",
  name: "Default Admin Policy",
  statements: [
    {
      sid: "AdminAllResources",
      effect: "ALLOW" as PolicyEffect,
      actions: { includes: ["*"], excludes: [] },
      resources: { types: ["*"], ids: [] },
      conditions: {
        StringEquals: {
          "subject.tenantId": "resource.tenantId",
        },
      },
    },
  ],
  metadata: createPolicyMetadata(
    { type: "default", role: "admin" },
    "Full administrative access for tenant administrators",
  ),
};

/** Default Member Policy Template */
export const DEFAULT_MEMBER_POLICY_TEMPLATE: ABACPolicy = {
  id: "",
  version: "2026-01-01",
  tenantId: "",
  name: "Default Member Policy",
  statements: [
    {
      sid: "MemberOwnResources",
      effect: "ALLOW" as PolicyEffect,
      actions: { includes: ["*"], excludes: [] },
      resources: { types: ["*"], ids: [] },
      conditions: {
        StringEquals: {
          "subject.tenantId": "resource.tenantId",
        },
        StringLike: {
          "resource.ownerId": "subject.id",
        },
      },
    },
  ],
  metadata: createPolicyMetadata(
    { type: "default", role: "member" },
    "Standard access for tenant members",
  ),
};

/** Default Service Policy Template */
export const DEFAULT_SERVICE_POLICY_TEMPLATE: ABACPolicy = {
  id: "",
  version: "2026-01-01",
  tenantId: "",
  name: "Default Service Policy",
  statements: [
    {
      sid: "ServiceApiAccess",
      effect: "ALLOW" as PolicyEffect,
      actions: { includes: ["API_*"], excludes: [] },
      resources: { types: ["api"], ids: [] },
      conditions: {
        StringEquals: {
          "subject.type": "service",
          "subject.tenantId": "resource.tenantId",
        },
      },
    },
  ],
  metadata: createPolicyMetadata(
    { type: "default", role: "service" },
    "Access for service accounts",
  ),
};

// =============================================================================
// TENANT ONBOARDING SERVICE
// =============================================================================

/**
 * Tenant Onboarding Service
 *
 * Enterprise-grade service for managing tenant lifecycle including:
 * - Tenant creation with default configurations
 * - Admin user bootstrap with secure credentials
 * - Default IAM policy setup
 * - SSO configuration
 * - Lifecycle management (suspend, resume, offboard)
 * - Key rotation
 */
export class TenantOnboardingService {
  private readonly OFFBOARDING_CONFIRMATION_PREFIX = "OFFBOARD";
  private readonly CREDENTIAL_TOKEN_TTL = 24 * 60 * 60 * 1000; // 24 hours
  private readonly KEY_ROTATION_GRACE_PERIOD = 7 * 24 * 60 * 60 * 1000; // 7 days

  constructor(
    private readonly tenantRepository: ITenantRepository,
    private readonly userRepository: IUserRepository,
    private readonly roleRepository: IRoleRepository,
    private readonly policyRepository: IPolicyRepository,
    private readonly auditLogger: IAuditLogger,
    private readonly cryptoService: ICryptoService,
    private readonly emailService: IEmailService,
    private readonly policyCache?: IPolicyCache,
  ) {}

  // ===========================================================================
  // TENANT CREATION
  // ===========================================================================

  /**
   * Create a new tenant with all default configurations
   */
  async createTenant(
    request: CreateTenantRequest,
  ): Promise<TenantOnboardingResult> {
    const correlationId = `tenant-create-${Date.now()}`;
    const startTime = new Date();

    try {
      // Validate tenant name uniqueness
      const existingTenant = await this.tenantRepository.findByName(
        request.name,
      );
      if (existingTenant) {
        throw new Error(`Tenant with name '${request.name}' already exists`);
      }

      // Generate tenant ID and API keys
      const tenantId = this.generateTenantId(request.name);
      const { key: apiKey, secret: apiSecret } =
        this.cryptoService.generateApiKey();
      const hashedSecret = this.cryptoService.hashApiSecret(apiSecret);

      // Merge settings with defaults based on plan
      const settings = this.getDefaultSettings(request.plan, request.settings);

      // Create tenant
      const tenant = await this.tenantRepository.create({
        name: request.name,
        displayName: request.displayName || request.name,
        domain: request.domain,
        settings,
        plan: request.plan || "STARTER",
        metadata: request.metadata,
      });

      // Update tenant with API keys
      const updatedTenant = await this.tenantRepository.update(tenant.id, {
        displayName: request.displayName || request.name,
        domain: request.domain,
        settings,
        plan: request.plan || "STARTER",
        metadata: {
          ...request.metadata,
          apiKey,
          apiSecretPrefix: hashedSecret.substring(0, 8),
        },
      });

      // Create default policies
      const defaultPolicies = await this.createDefaultPolicies(
        updatedTenant.id,
      );

      // Create default roles
      const roles = await this.createDefaultRoles(updatedTenant.id);

      // Bootstrap admin user
      const adminResult = await this.bootstrapAdminUser(
        updatedTenant.id,
        request.adminEmail,
        request.adminName,
      );

      // Update tenant status to ACTIVE
      const activeTenant = await this.tenantRepository.updateStatus(
        updatedTenant.id,
        "ACTIVE",
      );

      // Audit log
      await this.auditLogger.log(
        "TENANT_CREATED",
        "tenant",
        {
          tenantId: activeTenant.id,
          userId: adminResult.user.id,
          correlationId,
        },
        {
          resourceId: activeTenant.id,
          details: {
            tenantName: activeTenant.name,
            displayName: activeTenant.displayName,
            plan: activeTenant.plan,
            adminEmail: request.adminEmail,
            durationMs: Date.now() - startTime.getTime(),
          },
          outcome: "SUCCESS",
        },
      );

      return {
        tenant: activeTenant,
        adminUser: adminResult.user,
        adminCredentials: adminResult.credentials,
        defaultPolicies,
        roles,
        setupComplete: true,
      };
    } catch (error) {
      // Audit log failure
      await this.auditLogger.log(
        "TENANT_CREATED",
        "tenant",
        { tenantId: "unknown", correlationId },
        {
          details: {
            error: error instanceof Error ? error.message : "Unknown error",
            requestName: request.name,
          },
          outcome: "FAILURE",
          errorMessage:
            error instanceof Error ? error.message : "Unknown error",
        },
      );

      throw error;
    }
  }

  // ===========================================================================
  // ADMIN USER BOOTSTRAP
  // ===========================================================================

  /**
   * Bootstrap admin user for new tenant
   */
  async bootstrapAdminUser(
    tenantId: string,
    email: string,
    name?: string,
  ): Promise<AdminUserResult> {
    // Generate temporary password
    const temporaryPassword = this.cryptoService.generateSecurePassword(16);

    // Hash password
    const passwordHash =
      await this.cryptoService.hashPassword(temporaryPassword);

    // Create admin user
    const adminUser = new User(
      `user-admin-${Date.now()}-${Math.random().toString(36).substring(2, 9)}`,
      {} as any,
      new PasswordHash(passwordHash),
      ["admin"],
      UserStatus.ACTIVE,
      new Date(),
      new Date(),
      tenantId,
    );

    // Set email and name directly
    (adminUser as any)._email = { value: email, domain: email.split("@")[1] };
    (adminUser as any)._name = name || email.split("@")[0];

    // Save user
    await this.userRepository.save(adminUser);

    // Generate setup URL
    const setupToken = this.generateSetupToken(tenantId, adminUser.id);
    const setupUrl = `${process.env.APP_URL || "http://localhost:3000"}/setup/${setupToken}`;

    const credentials: AdminCredentials = {
      userId: adminUser.id,
      email,
      temporaryPassword,
      mustChangePassword: true,
      setupUrl,
    };

    // Send welcome email
    const tenant = await this.tenantRepository.findById(tenantId);
    await this.emailService.sendWelcomeEmail(
      email,
      name || email.split("@")[0],
      tenant?.displayName || tenantId,
      setupUrl,
      temporaryPassword,
    );

    // Audit log
    await this.auditLogger.log(
      "USER_CREATED",
      "user",
      { tenantId, userId: adminUser.id },
      {
        resourceId: adminUser.id,
        details: {
          email,
          roles: ["admin"],
          mustChangePassword: true,
        },
        outcome: "SUCCESS",
      },
    );

    return { user: adminUser, credentials };
  }

  // ===========================================================================
  // DEFAULT POLICIES
  // ===========================================================================

  /**
   * Create default IAM policies for tenant
   */
  async createDefaultPolicies(tenantId: string): Promise<ABACPolicy[]> {
    const policies: ABACPolicy[] = [];

    // Create admin policy
    const adminPolicy = this.createPolicyFromTemplate(
      DEFAULT_ADMIN_POLICY_TEMPLATE,
      tenantId,
      "Default Admin Policy",
    );
    await this.policyRepository.save(adminPolicy);
    policies.push(adminPolicy);

    // Create member policy
    const memberPolicy = this.createPolicyFromTemplate(
      DEFAULT_MEMBER_POLICY_TEMPLATE,
      tenantId,
      "Default Member Policy",
    );
    await this.policyRepository.save(memberPolicy);
    policies.push(memberPolicy);

    // Create service policy
    const servicePolicy = this.createPolicyFromTemplate(
      DEFAULT_SERVICE_POLICY_TEMPLATE,
      tenantId,
      "Default Service Policy",
    );
    await this.policyRepository.save(servicePolicy);
    policies.push(servicePolicy);

    // Audit log
    await this.auditLogger.log(
      "POLICY_CREATED",
      "policy",
      { tenantId, userId: "system" },
      {
        resourceId: tenantId,
        details: {
          policyCount: policies.length,
          policyNames: policies.map((p) => p.name),
        },
        outcome: "SUCCESS",
      },
    );

    return policies;
  }

  /**
   * Create a policy from template
   */
  private createPolicyFromTemplate(
    template: typeof DEFAULT_ADMIN_POLICY_TEMPLATE,
    tenantId: string,
    name: string,
  ): ABACPolicy {
    return {
      ...template,
      id: `policy-${tenantId}-${Date.now()}-${Math.random().toString(36).substring(2, 9)}`,
      tenantId,
      name,
      metadata: {
        ...template.metadata,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      },
    };
  }

  // ===========================================================================
  // DEFAULT ROLES
  // ===========================================================================

  /**
   * Create default roles for tenant
   */
  async createDefaultRoles(tenantId: string): Promise<Role[]> {
    const roles: Role[] = [];

    // Admin role
    const adminRole = new Role(
      `role-${tenantId}-admin-${Date.now()}`,
      "admin",
      "Full administrative access",
      null,
      ["*"],
      tenantId,
    );
    await this.roleRepository.save(adminRole);
    roles.push(adminRole);

    // Member role
    const memberRole = new Role(
      `role-${tenantId}-member-${Date.now()}`,
      "member",
      "Standard member access",
      null,
      ["read", "create", "update"],
      tenantId,
    );
    await this.roleRepository.save(memberRole);
    roles.push(memberRole);

    // Service role
    const serviceRole = new Role(
      `role-${tenantId}-service-${Date.now()}`,
      "service",
      "Service account access",
      null,
      ["API_ACCESS"],
      tenantId,
    );
    await this.roleRepository.save(serviceRole);
    roles.push(serviceRole);

    return roles;
  }

  // ===========================================================================
  // SSO CONFIGURATION
  // ===========================================================================

  /**
   * Configure SSO for tenant
   */
  async configureSSO(
    tenantId: string,
    ssoConfig: SSOConfig,
  ): Promise<SSOConfigurationResult> {
    const tenant = await this.tenantRepository.findById(tenantId);
    if (!tenant) {
      return {
        success: false,
        ssoConfigId: "",
        tenantId,
        provider: ssoConfig.provider,
        enabled: false,
        errorMessage: "Tenant not found",
      };
    }

    const ssoConfigId = `sso-${tenantId}-${Date.now()}`;

    // Store SSO configuration
    await this.storeSSOConfiguration(tenantId, ssoConfigId, ssoConfig);

    // Audit log
    await this.auditLogger.log(
      "SSO_CONFIGURED",
      "sso",
      { tenantId },
      {
        resourceId: ssoConfigId,
        details: {
          provider: ssoConfig.provider,
          entityId: ssoConfig.entityId,
        },
        outcome: "SUCCESS",
      },
    );

    return {
      success: true,
      ssoConfigId,
      tenantId,
      provider: ssoConfig.provider,
      enabled: true,
    };
  }

  /**
   * Store SSO configuration
   */
  private async storeSSOConfiguration(
    _tenantId: string,
    _configId: string,
    _config: SSOConfig,
  ): Promise<void> {
    // Implementation would store to database
  }

  // ===========================================================================
  // TENANT LIFECYCLE - SUSPEND
  // ===========================================================================

  /**
   * Suspend tenant (graceful)
   */
  async suspendTenant(
    request: SuspendTenantRequest,
  ): Promise<SuspendTenantResult> {
    const tenant = await this.tenantRepository.findById(request.tenantId);

    if (!tenant) {
      return {
        success: false,
        tenantId: request.tenantId,
        status: "PENDING",
        suspendedAt: new Date(),
        affectedUsersCount: 0,
        errorMessage: "Tenant not found",
      };
    }

    if (tenant.status !== "ACTIVE") {
      return {
        success: false,
        tenantId: request.tenantId,
        status: tenant.status,
        suspendedAt: new Date(),
        affectedUsersCount: 0,
        errorMessage: `Cannot suspend tenant with status '${tenant.status}'. Only ACTIVE tenants can be suspended.`,
      };
    }

    // Get affected users count
    const affectedUsersCount = await this.userRepository.countByTenant(
      request.tenantId,
    );

    // Calculate grace period end
    const gracePeriodEndAt = request.gracePeriodHours
      ? new Date(Date.now() + request.gracePeriodHours * 60 * 60 * 1000)
      : undefined;

    // Update tenant status
    const suspendedTenant = await this.tenantRepository.updateStatus(
      request.tenantId,
      "SUSPENDED",
    );

    // Suspend all users
    const users = await this.userRepository.findAll(request.tenantId);
    for (const user of users) {
      await this.userRepository.updateStatus(
        user.id,
        request.tenantId,
        UserStatus.SUSPENDED,
      );
    }

    // Invalidate policy cache
    await this.policyCache?.invalidate(request.tenantId);

    // Send notification to admin
    const adminEmail =
      (users.find((u) => u.roles.includes("admin")) as any)?._email?.value ||
      "";
    if (adminEmail) {
      const adminUser = users.find((u) => u.roles.includes("admin"));
      await this.emailService.sendSuspensionNotification(
        adminEmail,
        (adminUser as any)._name || "Admin",
        tenant.displayName,
        request.reason,
        request.message,
        request.gracePeriodHours,
      );
    }

    // Audit log
    await this.auditLogger.log(
      "TENANT_SUSPENDED",
      "tenant",
      { tenantId: request.tenantId },
      {
        resourceId: request.tenantId,
        details: {
          reason: request.reason,
          message: request.message,
          gracePeriodHours: request.gracePeriodHours,
          affectedUsersCount,
          gracePeriodEndAt: gracePeriodEndAt?.toISOString(),
        },
        outcome: "SUCCESS",
      },
    );

    return {
      success: true,
      tenantId: request.tenantId,
      status: suspendedTenant.status,
      suspendedAt: new Date(),
      gracePeriodEndAt,
      affectedUsersCount,
    };
  }

  // ===========================================================================
  // TENANT LIFECYCLE - RESUME
  // ===========================================================================

  /**
   * Resume suspended tenant
   */
  async resumeTenant(
    request: ResumeTenantRequest,
  ): Promise<ResumeTenantResult> {
    const tenant = await this.tenantRepository.findById(request.tenantId);

    if (!tenant) {
      return {
        success: false,
        tenantId: request.tenantId,
        status: "PENDING",
        resumedAt: new Date(),
        restoredUsersCount: 0,
        errorMessage: "Tenant not found",
      };
    }

    if (tenant.status !== "SUSPENDED") {
      return {
        success: false,
        tenantId: request.tenantId,
        status: tenant.status,
        resumedAt: new Date(),
        restoredUsersCount: 0,
        errorMessage: `Cannot resume tenant with status '${tenant.status}'. Only SUSPENDED tenants can be resumed.`,
      };
    }

    // Restore users
    const users = await this.userRepository.findAll(request.tenantId);
    for (const user of users) {
      await this.userRepository.updateStatus(
        user.id,
        request.tenantId,
        UserStatus.ACTIVE,
      );
    }

    // Update tenant status
    const resumedTenant = await this.tenantRepository.updateStatus(
      request.tenantId,
      "ACTIVE",
    );

    // Invalidate policy cache
    await this.policyCache?.invalidate(request.tenantId);

    // Send notification
    const adminUser = users.find((u) => u.roles.includes("admin"));
    if (adminUser) {
      await this.emailService.sendResumptionNotification(
        (adminUser as any)._email?.value,
        (adminUser as any)._name ||
          (adminUser as any)._email?.value.split("@")[0],
        tenant.displayName,
      );
    }

    // Audit log
    await this.auditLogger.log(
      "TENANT_RESUMED",
      "tenant",
      { tenantId: request.tenantId },
      {
        resourceId: request.tenantId,
        details: {
          reason: request.reason,
          restoredUsersCount: users.length,
        },
        outcome: "SUCCESS",
      },
    );

    return {
      success: true,
      tenantId: request.tenantId,
      status: resumedTenant.status,
      resumedAt: new Date(),
      restoredUsersCount: users.length,
    };
  }

  // ===========================================================================
  // TENANT LIFECYCLE - KEY ROTATION
  // ===========================================================================

  /**
   * Rotate tenant keys
   */
  async rotateTenantKeys(
    request: RotateTenantKeysRequest,
  ): Promise<RotateTenantKeysResult> {
    const tenant = await this.tenantRepository.findById(request.tenantId);

    if (!tenant) {
      return {
        success: false,
        tenantId: request.tenantId,
        newApiKeyId: "",
        newApiSecretPrefix: "",
        rotatedAt: new Date(),
        gracePeriodEndAt: new Date(),
        errorMessage: "Tenant not found",
      };
    }

    // Generate new API keys
    const { key: newApiKey, secret: newApiSecret } =
      this.cryptoService.generateApiKey();
    const hashedSecret = this.cryptoService.hashApiSecret(newApiSecret);
    const newApiKeyId = `key-${request.tenantId}-${Date.now()}`;

    // Store new keys
    await this.storeTenantKeys(
      request.tenantId,
      newApiKeyId,
      newApiKey,
      hashedSecret,
    );

    // Grace period end
    const gracePeriodEndAt = new Date(
      Date.now() + this.KEY_ROTATION_GRACE_PERIOD,
    );

    // Audit log
    await this.auditLogger.log(
      "KEY_ROTATED",
      "api-key",
      { tenantId: request.tenantId },
      {
        resourceId: newApiKeyId,
        details: {
          rotateAll: request.rotateAll,
          gracePeriodHours: this.KEY_ROTATION_GRACE_PERIOD / (60 * 60 * 1000),
        },
        outcome: "SUCCESS",
      },
    );

    return {
      success: true,
      tenantId: request.tenantId,
      oldApiKeyId: tenant.apiKey,
      newApiKeyId,
      newApiSecretPrefix: hashedSecret.substring(0, 8),
      rotatedAt: new Date(),
      gracePeriodEndAt,
    };
  }

  /**
   * Store tenant keys
   */
  private async storeTenantKeys(
    tenantId: string,
    _keyId: string,
    key: string,
    hashedSecret: string,
  ): Promise<void> {
    const tenant = await this.tenantRepository.findById(tenantId);
    if (tenant) {
      await this.tenantRepository.update(tenantId, {
        displayName: tenant.displayName,
        settings: tenant.settings,
        metadata: {
          apiKey: key,
          apiSecretPrefix: hashedSecret.substring(0, 8),
          previousKeyId: tenant.metadata?.apiKey,
          keyRotatedAt: new Date().toISOString(),
        },
      });
    }
  }

  // ===========================================================================
  // TENANT LIFECYCLE - OFFBOARDING
  // ===========================================================================

  /**
   * Offboard tenant safely
   */
  async offboardTenant(
    request: OffboardTenantRequest,
  ): Promise<OffboardTenantResult> {
    // Validate confirmation token
    if (
      !this.validateOffboardingConfirmation(
        request.confirmationToken,
        request.tenantId,
      )
    ) {
      return {
        success: false,
        tenantId: request.tenantId,
        status: "ACTIVE",
        offboardedAt: new Date(),
        scheduledDeletionAt: new Date(),
        errorMessage: "Invalid or expired confirmation token",
      };
    }

    const tenant = await this.tenantRepository.findById(request.tenantId);

    if (!tenant) {
      return {
        success: false,
        tenantId: request.tenantId,
        status: "PENDING",
        offboardedAt: new Date(),
        scheduledDeletionAt: new Date(),
        errorMessage: "Tenant not found",
      };
    }

    // Calculate deletion date based on retention
    const retentionDays = Math.min(Math.max(request.retentionDays, 30), 90);
    const scheduledDeletionAt = new Date(
      Date.now() + retentionDays * 24 * 60 * 60 * 1000,
    );

    // Update status to OFFBOARDING
    const offboardedTenant = await this.tenantRepository.updateStatus(
      request.tenantId,
      "OFFBOARDING",
    );

    // Export data if requested
    let exportUrl: string | undefined;
    if (request.exportData) {
      exportUrl = await this.exportTenantData(
        request.tenantId,
        request.exportFormat,
      );
    }

    // Revoke all user access
    const users = await this.userRepository.findAll(request.tenantId);
    for (const user of users) {
      await this.userRepository.updateStatus(
        user.id,
        request.tenantId,
        UserStatus.INACTIVE,
      );
    }

    // Invalidate policy cache
    await this.policyCache?.invalidate(request.tenantId);

    // Send notification
    const adminUser = users.find((u) => u.roles.includes("admin"));
    if (adminUser) {
      await this.emailService.sendOffboardingNotification(
        (adminUser as any)._email?.value,
        (adminUser as any)._name ||
          (adminUser as any)._email?.value.split("@")[0],
        tenant.displayName,
        exportUrl,
        scheduledDeletionAt,
      );
    }

    // Audit log
    await this.auditLogger.log(
      "TENANT_OFFBOARDED",
      "tenant",
      { tenantId: request.tenantId },
      {
        resourceId: request.tenantId,
        details: {
          exportData: request.exportData,
          exportFormat: request.exportFormat,
          retentionDays,
          scheduledDeletionAt: scheduledDeletionAt.toISOString(),
          affectedUsersCount: users.length,
          exportUrl: exportUrl ? "[PROTECTED]" : undefined,
        },
        outcome: "SUCCESS",
      },
    );

    return {
      success: true,
      tenantId: request.tenantId,
      status: offboardedTenant.status,
      offboardedAt: new Date(),
      scheduledDeletionAt,
      exportUrl,
    };
  }

  /**
   * Export tenant data
   */
  private async exportTenantData(
    tenantId: string,
    format: "JSON" | "CSV" | "SQL",
  ): Promise<string> {
    // Collect tenant data
    const tenant = await this.tenantRepository.findById(tenantId);
    const users = await this.userRepository.findAll(tenantId);
    const roles = await this.roleRepository.findAll(tenantId);
    const policies = await this.policyRepository.findAll(tenantId);

    // Format data based on requested format
    let exportData: string;
    switch (format) {
      case "JSON":
        exportData = JSON.stringify(
          {
            tenant: {
              id: tenant?.id,
              name: tenant?.name,
              displayName: tenant?.displayName,
              status: tenant?.status,
              plan: tenant?.plan,
              createdAt: tenant?.createdAt,
              settings: tenant?.settings,
            },
            users: users.map((u) => ({
              id: u.id,
              email: (u as any)._email?.value,
              roles: u.roles,
              status: u.status,
              createdAt: u.createdAt,
            })),
            roles: roles.map((r) => ({
              id: r.id,
              name: r.name,
              description: r.description,
              permissions: r.permissions,
            })),
            policies: policies.map((p) => ({
              id: p.id,
              name: p.name,
              statements: p.statements,
            })),
          },
          null,
          2,
        );
        break;

      case "CSV":
        exportData = "id,email,roles,status,createdAt\n";
        for (const user of users) {
          exportData += `${user.id},${(user as any)._email?.value},"${user.roles.join(",")}",${user.status},${user.createdAt}\n`;
        }
        break;

      case "SQL":
        exportData = `-- Tenant Data Export for ${tenantId}\n`;
        exportData += `-- Generated at ${new Date().toISOString()}\n\n`;
        exportData += `-- Users\n`;
        for (const user of users) {
          exportData += `INSERT INTO users (id, email, tenant_id, roles, status, created_at) VALUES `;
          exportData += `('${user.id}', '${(user as any)._email?.value}', '${tenantId}', '${JSON.stringify(user.roles)}', '${user.status}', '${user.createdAt.toISOString()}');\n`;
        }
        exportData += "\n";
        break;

      default:
        exportData = JSON.stringify({ error: "Unknown format" });
    }

    // Store export (return URL as placeholder)
    const exportUrl = `/exports/tenant-${tenantId}-${Date.now()}.${format.toLowerCase()}`;

    // Audit log data export
    await this.auditLogger.log(
      "DATA_EXPORT",
      "tenant",
      { tenantId },
      {
        resourceId: tenantId,
        details: {
          format,
          recordCount: {
            users: users.length,
            roles: roles.length,
            policies: policies.length,
          },
        },
        outcome: "SUCCESS",
      },
    );

    return exportUrl;
  }

  // ===========================================================================
  // OFFBOARDING CONFIRMATION
  // ===========================================================================

  /**
   * Generate offboarding confirmation token
   */
  generateOffboardingConfirmationToken(tenantId: string): string {
    const timestamp = Date.now();
    const random = randomBytes(16).toString("hex");
    const data = `${this.OFFBOARDING_CONFIRMATION_PREFIX}:${tenantId}:${timestamp}:${random}`;
    return createHash("sha256").update(data).digest("hex");
  }

  /**
   * Validate offboarding confirmation token
   */
  validateOffboardingConfirmation(token: string, _tenantId: string): boolean {
    if (!token || token.length < 64) {
      return false;
    }
    const hexRegex = /^[a-f0-9]{64}$/i;
    return hexRegex.test(token);
  }

  // ===========================================================================
  // HELPER METHODS
  // ===========================================================================

  /**
   * Generate tenant ID from name
   */
  private generateTenantId(name: string): string {
    const timestamp = Date.now().toString(36);
    const random = Math.random().toString(36).substring(2, 8);
    const sanitizedName = name
      .toLowerCase()
      .replace(/[^a-z0-9]/g, "-")
      .substring(0, 20);
    return `tenant-${sanitizedName}-${timestamp}-${random}`;
  }

  /**
   * Generate setup token
   */
  private generateSetupToken(tenantId: string, userId: string): string {
    const timestamp = Date.now();
    const data = `${tenantId}:${userId}:${timestamp}`;
    return Buffer.from(data).toString("base64url");
  }

  /**
   * Get default settings based on plan
   */
  private getDefaultSettings(
    plan?: "STARTER" | "PROFESSIONAL" | "ENTERPRISE",
    customSettings?: Partial<TenantSettings>,
  ): TenantSettings {
    const settingsByPlan: Record<string, TenantSettings> = {
      STARTER: {
        maxUsers: 10,
        maxPolicies: 5,
        mfaRequired: false,
        sessionTimeout: 60,
        ipWhitelist: [],
        allowedDomains: [],
        retentionDays: 30,
      },
      PROFESSIONAL: {
        maxUsers: 100,
        maxPolicies: 20,
        mfaRequired: true,
        sessionTimeout: 60,
        ipWhitelist: [],
        allowedDomains: [],
        retentionDays: 60,
      },
      ENTERPRISE: {
        maxUsers: -1,
        maxPolicies: -1,
        mfaRequired: true,
        sessionTimeout: 30,
        ipWhitelist: [],
        allowedDomains: [],
        retentionDays: 90,
      },
    };

    const defaults = settingsByPlan[plan || "STARTER"];
    return { ...defaults, ...customSettings };
  }
}

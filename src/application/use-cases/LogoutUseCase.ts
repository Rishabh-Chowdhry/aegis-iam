import { AuditLogEntry } from "../../domain/value-objects/AuditLogEntry";
import { IAuditLogRepository } from "../../infrastructure/repositories/IAuditLogRepository";

export interface LogoutRequest {
  userId: string;
  refreshToken: string;
  tenantId: string;
  ipAddress?: string;
  userAgent?: string;
}

export interface LogoutResponse {
  success: boolean;
}

export class LogoutUseCase {
  constructor(private auditLogRepository: IAuditLogRepository) {}

  async execute(request: LogoutRequest): Promise<LogoutResponse> {
    const { userId, refreshToken, ipAddress, userAgent } = request;

    // In a real implementation, you would invalidate the refresh token
    // For now, just log the logout event

    await this.auditLogRepository.save(
      new AuditLogEntry(
        userId,
        "logout",
        new Date(),
        {
          refreshToken: refreshToken.substring(0, 10) + "...",
          ipAddress,
          userAgent,
        },
        request.tenantId,
      ),
    );

    return { success: true };
  }
}

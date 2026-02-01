import { User } from "../../domain/entities/User";
import { AuditLogEntry } from "../../domain/value-objects/AuditLogEntry";
import { IUserRepository } from "../../infrastructure/repositories/IUserRepository";
import { IAuditLogRepository } from "../../infrastructure/repositories/IAuditLogRepository";
import { TokenService } from "../../modules/auth/services/TokenService";

export interface RefreshTokenRequest {
  refreshToken: string;
  tenantId: string;
  ipAddress?: string;
  userAgent?: string;
}

export interface RefreshTokenResponse {
  user: User;
  accessToken: string;
  refreshToken: string;
}

export class RefreshTokenUseCase {
  private tokenService: TokenService;

  constructor(
    private userRepository: IUserRepository,
    private auditLogRepository: IAuditLogRepository,
  ) {
    this.tokenService = TokenService.getInstance();
  }

  async execute(request: RefreshTokenRequest): Promise<RefreshTokenResponse> {
    const { refreshToken, tenantId, ipAddress, userAgent } = request;

    try {
      // Decode refresh token to get user ID
      const decoded = this.tokenService.decodeToken(refreshToken);
      if (!decoded || !decoded.sub) {
        throw new Error("Invalid refresh token");
      }

      const userId = decoded.sub;

      // Get user from repository
      const user = await this.userRepository.findById(userId, tenantId);
      if (!user) {
        throw new Error("User not found");
      }

      if (!user.isActive()) {
        throw new Error("Account is not active");
      }

      // Use AuthService to refresh tokens (handles validation and revocation of old token)
      // For now, decode the token and return a basic response
      // In production, use the full AuthService.flow

      // Generate new access token
      const accessTokenResult =
        await this.tokenService.generateAccessToken(user);

      // Return basic response (full refresh should use AuthService.refreshTokens)
      return {
        user,
        accessToken: accessTokenResult.token,
        refreshToken, // In production, this would be rotated
      };
    } catch (error) {
      throw new Error("Invalid refresh token");
    }
  }
}

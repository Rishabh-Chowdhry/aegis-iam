import { User } from "../../domain/entities/User";
import { Email } from "../../domain/value-objects/Email";
import { AuditLogEntry } from "../../domain/value-objects/AuditLogEntry";
import { IUserRepository } from "../../infrastructure/repositories/IUserRepository";
import { IAuditLogRepository } from "../../infrastructure/repositories/IAuditLogRepository";
import jwt from "jsonwebtoken";

export interface LoginRequest {
  email: string;
  password: string;
  tenantId: string;
  ipAddress?: string;
  userAgent?: string;
}

export interface LoginResponse {
  user: User;
  accessToken: string;
  refreshToken: string;
}

export class LoginUseCase {
  constructor(
    private userRepository: IUserRepository,
    private auditLogRepository: IAuditLogRepository,
  ) {}

  async execute(request: LoginRequest): Promise<LoginResponse> {
    const { email, password, tenantId, ipAddress, userAgent } = request;

    // Find user by email
    const user = await this.userRepository.findByEmail(email, tenantId);
    if (!user) {
      throw new Error("Invalid credentials");
    }

    // Check if user is active
    if (!user.isActive()) {
      throw new Error("Account is not active");
    }

    // Verify password
    const isPasswordValid = await user.hashedPassword.verifyPassword(password);
    if (!isPasswordValid) {
      // Log failed login attempt
      await this.auditLogRepository.save(
        new AuditLogEntry(
          user.id,
          "login_failed",
          new Date(),
          {
            reason: "invalid_password",
            email,
            ipAddress,
            userAgent,
          },
          request.tenantId,
        ),
      );
      throw new Error("Invalid credentials");
    }

    // Generate tokens
    const accessToken = jwt.sign(
      { userId: user.id, email: user.email.value, roles: user.roles, tenantId },
      process.env.JWT_SECRET || "default-secret",
      { expiresIn: "15m" },
    );

    const refreshToken = jwt.sign(
      { userId: user.id, tokenType: "refresh" },
      process.env.JWT_REFRESH_SECRET || "default-refresh-secret",
      { expiresIn: "7d" },
    );

    // Log successful login
    await this.auditLogRepository.save(
      new AuditLogEntry(
        user.id,
        "login_success",
        new Date(),
        {
          ipAddress,
          userAgent,
        },
        tenantId,
      ),
    );

    return {
      user,
      accessToken,
      refreshToken,
    };
  }
}

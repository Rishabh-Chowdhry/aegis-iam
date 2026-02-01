import { User, UserStatus } from "../../domain/entities/User";
import { Email } from "../../domain/value-objects/Email";
import { PasswordHash } from "../../domain/value-objects/PasswordHash";
import { AuditLogEntry } from "../../domain/value-objects/AuditLogEntry";
import { IUserRepository } from "../../infrastructure/repositories/IUserRepository";
import { IAuditLogRepository } from "../../infrastructure/repositories/IAuditLogRepository";

export interface CreateUserRequest {
  email: string;
  password: string;
  roles?: string[];
  tenantId: string;
  performedBy: string; // User ID of the person performing the action
}

export interface CreateUserResponse {
  user: User;
}

export class CreateUserUseCase {
  constructor(
    private userRepository: IUserRepository,
    private auditLogRepository: IAuditLogRepository,
  ) {}

  async execute(request: CreateUserRequest): Promise<CreateUserResponse> {
    const { email, password, roles = [], tenantId, performedBy } = request;

    // Check if user already exists
    const existingUser = await this.userRepository.findByEmail(email, tenantId);
    if (existingUser) {
      throw new Error("User with this email already exists");
    }

    // Create domain objects
    const emailVO = new Email(email);
    const passwordHash = await PasswordHash.fromPlainPassword(password);

    // Generate unique ID (in real implementation, use UUID)
    const userId = `user-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;

    const user = new User(
      userId,
      emailVO,
      passwordHash,
      roles,
      UserStatus.ACTIVE, // Default status
      new Date(),
      new Date(),
      tenantId,
    );

    // Save user
    await this.userRepository.save(user);

    // Log audit entry
    const auditEntry = new AuditLogEntry(
      performedBy,
      "USER_CREATED",
      new Date(),
      {
        userId: user.id,
        email: user.email.value,
        tenantId,
      },
      tenantId,
    );
    await this.auditLogRepository.save(auditEntry);

    return { user };
  }
}

import { PrismaClient } from "@prisma/client";
import { User, UserStatus } from "../../domain/entities/User";
import { Email } from "../../domain/value-objects/Email";
import { PasswordHash } from "../../domain/value-objects/PasswordHash";
import { IUserRepository } from "./IUserRepository";

export class PrismaUserRepository implements IUserRepository {
  constructor(private prisma: PrismaClient) {}

  async findById(id: string, tenantId: string): Promise<User | null> {
    const userData = await this.prisma.user.findFirst({
      where: { id, tenantId },
    });
    if (!userData) return null;
    return this.mapToDomain(userData);
  }

  async findByEmail(email: string, tenantId: string): Promise<User | null> {
    const userData = await this.prisma.user.findFirst({
      where: { email, tenantId },
    });
    if (!userData) return null;
    return this.mapToDomain(userData);
  }

  async findAll(tenantId: string): Promise<User[]> {
    const usersData = await this.prisma.user.findMany({
      where: { tenantId },
    });
    return usersData.map(this.mapToDomain);
  }

  async save(user: User): Promise<void> {
    await this.prisma.user.create({
      data: {
        id: user.id,
        email: user.email.value,
        passwordHash: user.hashedPassword.hash, // Map domain 'hashedPassword' to Prisma 'passwordHash'
        roles: user.roles,
        status: user.status,
        tenantId: user.tenantId,
        createdAt: user.createdAt,
        updatedAt: user.updatedAt,
      } as any,
    });
  }

  async update(user: User): Promise<void> {
    await this.prisma.user.update({
      where: { id: user.id },
      data: {
        email: user.email.value,
        passwordHash: user.hashedPassword.hash,
        roles: user.roles,
        status: user.status,
        updatedAt: user.updatedAt,
      } as any,
    });
  }

  async delete(id: string, tenantId: string): Promise<void> {
    await this.prisma.user.deleteMany({
      where: { id, tenantId },
    });
  }

  async exists(id: string, tenantId: string): Promise<boolean> {
    const count = await this.prisma.user.count({
      where: { id, tenantId },
    });
    return count > 0;
  }

  private mapToDomain(userData: any): User {
    return new User(
      userData.id,
      new Email(userData.email),
      new PasswordHash(userData.passwordHash), // Map Prisma 'passwordHash' to domain 'hashedPassword'
      userData.roles,
      userData.status as UserStatus,
      userData.createdAt,
      userData.updatedAt,
      userData.tenantId,
    );
  }
}

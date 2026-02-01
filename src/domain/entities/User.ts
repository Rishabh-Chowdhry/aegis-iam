import { Email } from "../value-objects/Email";
import { PasswordHash } from "../value-objects/PasswordHash";

enum UserStatus {
  ACTIVE = "active",
  INACTIVE = "inactive",
  SUSPENDED = "suspended",
}

class User {
  private _id: string;
  private _email: Email;
  private _hashedPassword: PasswordHash;
  private _roles: string[]; // Array of role IDs
  private _status: UserStatus;
  private _createdAt: Date;
  private _updatedAt: Date;
  private _tenantId: string;

  constructor(
    id: string,
    email: Email,
    hashedPassword: PasswordHash,
    roles: string[],
    status: UserStatus,
    createdAt: Date,
    updatedAt: Date,
    tenantId: string,
  ) {
    // Invariants
    if (!id) throw new Error("User ID is required");
    if (!tenantId) throw new Error("Tenant ID is required");
    if (createdAt > updatedAt)
      throw new Error("CreatedAt cannot be after UpdatedAt");

    this._id = id;
    this._email = email;
    this._hashedPassword = hashedPassword;
    this._roles = [...roles]; // Defensive copy
    this._status = status;
    this._createdAt = createdAt;
    this._updatedAt = updatedAt;
    this._tenantId = tenantId;
  }

  // Getters
  get id(): string {
    return this._id;
  }
  get email(): Email {
    return this._email;
  }
  get hashedPassword(): PasswordHash {
    return this._hashedPassword;
  }
  get roles(): string[] {
    return [...this._roles];
  } // Defensive copy
  get status(): UserStatus {
    return this._status;
  }
  get createdAt(): Date {
    return this._createdAt;
  }
  get updatedAt(): Date {
    return this._updatedAt;
  }
  get tenantId(): string {
    return this._tenantId;
  }

  // Business logic methods
  addRole(roleId: string): void {
    if (!this._roles.includes(roleId)) {
      this._roles.push(roleId);
      this._updatedAt = new Date();
    }
  }

  removeRole(roleId: string): void {
    this._roles = this._roles.filter((r) => r !== roleId);
    this._updatedAt = new Date();
  }

  changeStatus(newStatus: UserStatus): void {
    this._status = newStatus;
    this._updatedAt = new Date();
  }

  updateEmail(newEmail: Email): void {
    this._email = newEmail;
    this._updatedAt = new Date();
  }

  updatePassword(newHash: PasswordHash): void {
    this._hashedPassword = newHash;
    this._updatedAt = new Date();
  }

  hasRole(roleId: string): boolean {
    return this._roles.includes(roleId);
  }

  isActive(): boolean {
    return this._status === UserStatus.ACTIVE;
  }
}

export { User, UserStatus };

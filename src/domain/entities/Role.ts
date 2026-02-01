class Role {
  private _id: string;
  private _name: string;
  private _description: string;
  private _parentId: string | null;
  private _permissions: string[]; // Array of permission IDs
  private _tenantId: string;
  private _createdAt: Date;
  private _updatedAt: Date;

  constructor(
    id: string,
    name: string,
    description: string,
    parentId: string | null,
    permissions: string[],
    tenantId: string,
    createdAt: Date = new Date(),
    updatedAt: Date = new Date(),
  ) {
    // Invariants
    if (!id) throw new Error("Role ID is required");
    if (!name.trim()) throw new Error("Role name is required");
    if (!tenantId) throw new Error("Tenant ID is required");
    if (parentId === id) throw new Error("Role cannot be its own parent");

    this._id = id;
    this._name = name;
    this._description = description;
    this._parentId = parentId;
    this._permissions = [...permissions]; // Defensive copy
    this._tenantId = tenantId;
    this._createdAt = createdAt;
    this._updatedAt = updatedAt;
  }

  // Getters
  get id(): string {
    return this._id;
  }
  get name(): string {
    return this._name;
  }
  get description(): string {
    return this._description;
  }
  get parentId(): string | null {
    return this._parentId;
  }
  get permissions(): string[] {
    return [...this._permissions];
  } // Defensive copy
  get tenantId(): string {
    return this._tenantId;
  }
  get createdAt(): Date {
    return this._createdAt;
  }
  get updatedAt(): Date {
    return this._updatedAt;
  }

  // Business logic methods
  addPermission(permissionId: string): void {
    if (!this._permissions.includes(permissionId)) {
      this._permissions.push(permissionId);
    }
  }

  removePermission(permissionId: string): void {
    this._permissions = this._permissions.filter((p) => p !== permissionId);
  }

  hasPermission(permissionId: string): boolean {
    return this._permissions.includes(permissionId);
  }

  updateDescription(newDescription: string): void {
    this._description = newDescription;
  }

  setParentRole(parentId: string | null): void {
    if (parentId === this._id) throw new Error("Role cannot be its own parent");
    this._parentId = parentId;
  }
}

export { Role };

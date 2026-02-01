class Permission {
  private _id: string;
  private _name: string;
  private _resource: string;
  private _action: string;
  private _description: string;
  private _tenantId: string;

  constructor(
    id: string,
    name: string,
    resource: string,
    action: string,
    description: string,
    tenantId: string,
  ) {
    // Invariants
    if (!id) throw new Error("Permission ID is required");
    if (!name.trim()) throw new Error("Permission name is required");
    if (!resource.trim()) throw new Error("Resource is required");
    if (!action.trim()) throw new Error("Action is required");
    if (!tenantId) throw new Error("Tenant ID is required");

    this._id = id;
    this._name = name;
    this._resource = resource;
    this._action = action;
    this._description = description;
    this._tenantId = tenantId;
  }

  // Getters
  get id(): string {
    return this._id;
  }
  get name(): string {
    return this._name;
  }
  get resource(): string {
    return this._resource;
  }
  get action(): string {
    return this._action;
  }
  get description(): string {
    return this._description;
  }
  get tenantId(): string {
    return this._tenantId;
  }

  // Business logic methods
  matches(resource: string, action: string): boolean {
    return this._resource === resource && this._action === action;
  }

  updateName(newName: string): void {
    if (!newName.trim()) throw new Error("Permission name is required");
    this._name = newName;
  }
}

export { Permission };

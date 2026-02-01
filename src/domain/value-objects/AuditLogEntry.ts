export class AuditLogEntry {
  private _userId: string;
  private _action: string;
  private _timestamp: Date;
  private _details: Record<string, any>;
  private _tenantId: string;

  constructor(
    userId: string,
    action: string,
    timestamp: Date,
    details: Record<string, any>,
    tenantId: string,
  ) {
    if (!userId) throw new Error("User ID is required");
    if (!action.trim()) throw new Error("Action is required");
    if (!tenantId) throw new Error("Tenant ID is required");

    this._userId = userId;
    this._action = action;
    this._timestamp = timestamp;
    this._details = { ...details }; // Defensive copy
    this._tenantId = tenantId;
  }

  // Getters
  get userId(): string {
    return this._userId;
  }
  get action(): string {
    return this._action;
  }
  get timestamp(): Date {
    return this._timestamp;
  }
  get details(): Record<string, any> {
    return { ...this._details };
  } // Defensive copy
  get tenantId(): string {
    return this._tenantId;
  }

  toJSON(): Record<string, any> {
    return {
      userId: this._userId,
      action: this._action,
      timestamp: this._timestamp.toISOString(),
      details: this._details,
      tenantId: this._tenantId,
    };
  }
}

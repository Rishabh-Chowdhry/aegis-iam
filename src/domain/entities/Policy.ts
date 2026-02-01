type PolicyEffect = "allow" | "deny";

class Policy {
  private _id: string;
  private _name: string;
  private _conditions: Record<string, any>; // JSON object for ABAC rules
  private _effect: PolicyEffect;
  private _description: string;
  private _tenantId: string;

  constructor(
    id: string,
    name: string,
    conditions: Record<string, any>,
    effect: PolicyEffect,
    description: string,
    tenantId: string,
  ) {
    // Invariants
    if (!id) throw new Error("Policy ID is required");
    if (!name.trim()) throw new Error("Policy name is required");
    if (!tenantId) throw new Error("Tenant ID is required");

    this._id = id;
    this._name = name;
    this._conditions = { ...conditions }; // Defensive copy
    this._effect = effect;
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
  get conditions(): Record<string, any> {
    return { ...this._conditions };
  } // Defensive copy
  get effect(): PolicyEffect {
    return this._effect;
  }
  get description(): string {
    return this._description;
  }
  get tenantId(): string {
    return this._tenantId;
  }

  // Business logic methods
  evaluate(context: Record<string, any>): boolean {
    // Simple evaluation: check if all conditions match the context
    // In a real implementation, this could use a more sophisticated rule engine
    for (const [key, value] of Object.entries(this._conditions)) {
      if (context[key] !== value) {
        return false;
      }
    }
    return true;
  }

  updateConditions(newConditions: Record<string, any>): void {
    this._conditions = { ...newConditions };
  }

  updateName(newName: string): void {
    if (!newName.trim()) throw new Error("Policy name is required");
    this._name = newName;
  }

  updateDescription(newDescription: string): void {
    this._description = newDescription;
  }
}

export { Policy, PolicyEffect };

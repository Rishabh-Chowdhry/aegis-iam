class TokenId {
  private _value: string;

  constructor(value?: string) {
    this._value = value || this.generateUniqueId();
  }

  private generateUniqueId(): string {
    // In a real implementation, use crypto.randomUUID() or similar
    return (
      "unique-token-id-" +
      Date.now() +
      "-" +
      Math.random().toString(36).substr(2, 9)
    );
  }

  get value(): string {
    return this._value;
  }

  equals(other: TokenId): boolean {
    return this._value === other._value;
  }

  toString(): string {
    return this._value;
  }
}

export { TokenId };

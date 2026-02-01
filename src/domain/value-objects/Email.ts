class Email {
  private _value: string;

  constructor(value: string) {
    if (!this.isValidEmail(value)) {
      throw new Error("Invalid email format");
    }
    this._value = value.toLowerCase(); // Normalize to lowercase
  }

  private isValidEmail(email: string): boolean {
    const regex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return regex.test(email);
  }

  get value(): string {
    return this._value;
  }

  equals(other: Email): boolean {
    return this._value === other._value;
  }

  toString(): string {
    return this._value;
  }
}

export { Email };

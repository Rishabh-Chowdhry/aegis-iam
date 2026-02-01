import { hash, verify, argon2id } from "argon2";

class PasswordHash {
  private _hash: string;

  constructor(hash: string) {
    if (!hash) {
      throw new Error("Password hash is required");
    }
    this._hash = hash;
  }

  get hash(): string {
    return this._hash;
  }

  // Static factory method to create hash from plain password
  static async fromPlainPassword(password: string): Promise<PasswordHash> {
    const hashed = await hash(password, { type: argon2id });
    return new PasswordHash(hashed);
  }

  // Method to verify plain password against hash
  async verifyPassword(password: string): Promise<boolean> {
    return await verify(this._hash, password);
  }

  equals(other: PasswordHash): boolean {
    return this._hash === other._hash;
  }
}

export { PasswordHash };

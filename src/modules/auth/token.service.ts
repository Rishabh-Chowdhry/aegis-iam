import jwt from "jsonwebtoken";

class TokenService {
  static generateAccessToken(userId: string) {
    const secret = process.env.ACCESS_TOKEN_SECRET || "default-secret";
    return jwt.sign({ userId }, secret, {
      expiresIn: "15m",
    });
  }

  static generateRefreshToken(userId: string) {
    const secret = process.env.REFRESH_TOKEN_SECRET || "default-refresh-secret";
    return jwt.sign({ userId }, secret, {
      expiresIn: "7d",
    });
  }

  // Additional methods for token validation, etc.
}

export default TokenService;

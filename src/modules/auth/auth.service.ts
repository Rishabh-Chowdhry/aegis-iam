/**
 * Legacy Auth Service - Simple JWT Operations
 *
 * This is a lightweight auth service for basic JWT operations.
 * For full authentication features, use the services/AuthService.
 */

import jwt from "jsonwebtoken";
import { ResponseStatus } from "../../shared/errors/ResponseStatus";
import { StatusMapping } from "../../shared/errors/StatusMapping";
import { RegisterInput, LoginInput } from "./auth.schemas";
import { IUserRepository } from "../../infrastructure/repositories/IUserRepository";

class AuthService {
  constructor(private userRepository?: IUserRepository) {}

  async register(userData: RegisterInput) {
    // TODO: Implement with repository
    return StatusMapping.createResponse(ResponseStatus.CREATED);
  }

  async login(loginData: LoginInput) {
    // TODO: Implement with repository
    return StatusMapping.createErrorResponse(
      ResponseStatus.UNAUTHORIZED,
      "Login not implemented",
    );
  }

  async verifyToken(token: string) {
    const secret = process.env.ACCESS_TOKEN_SECRET || "default-secret";
    return jwt.verify(token, secret);
  }

  // Additional methods for logout, refresh token, etc.
}

export default AuthService;

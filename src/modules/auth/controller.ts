import { Request, Response } from "express";
import { LoginUseCase } from "../../application/use-cases/LoginUseCase";
import { LogoutUseCase } from "../../application/use-cases/LogoutUseCase";
import { RefreshTokenUseCase } from "../../application/use-cases/RefreshTokenUseCase";
import { LoginInput, LogoutInput, RefreshTokenInput } from "./schemas";
import { StatusMapping } from "../../shared/errors/StatusMapping";
import { ResponseStatus } from "../../shared/errors/ResponseStatus";

export class AuthController {
  constructor(
    private loginUseCase: LoginUseCase,
    private logoutUseCase: LogoutUseCase,
    private refreshTokenUseCase: RefreshTokenUseCase,
  ) {}

  async login(req: Request<{}, {}, LoginInput>, res: Response) {
    try {
      const { email, password, tenantId } = req.body;
      const ipAddress = req.ip;
      const userAgent = req.get("User-Agent");

      const result = await this.loginUseCase.execute({
        email,
        password,
        tenantId,
        ipAddress,
        userAgent,
      });

      res.status(ResponseStatus.OK).json(
        StatusMapping.createResponse(ResponseStatus.OK, {
          user: {
            id: result.user.id,
            email: result.user.email.value,
            roles: result.user.roles,
            status: result.user.status,
          },
          accessToken: result.accessToken,
          refreshToken: result.refreshToken,
        }),
      );
    } catch (error) {
      res
        .status(ResponseStatus.UNAUTHORIZED)
        .json(
          StatusMapping.createErrorResponse(
            ResponseStatus.UNAUTHORIZED,
            error instanceof Error ? error.message : "Login failed",
          ),
        );
    }
  }

  async logout(req: Request<{}, {}, LogoutInput>, res: Response) {
    try {
      const { refreshToken, tenantId } = req.body;
      const userId = (req as any).user?.userId; // From auth middleware
      const ipAddress = req.ip;
      const userAgent = req.get("User-Agent");

      await this.logoutUseCase.execute({
        userId,
        refreshToken,
        tenantId,
        ipAddress,
        userAgent,
      });

      res.status(ResponseStatus.OK).json(
        StatusMapping.createResponse(ResponseStatus.OK, {
          message: "Logged out successfully",
        }),
      );
    } catch (error) {
      res
        .status(ResponseStatus.BAD_REQUEST)
        .json(
          StatusMapping.createErrorResponse(
            ResponseStatus.BAD_REQUEST,
            error instanceof Error ? error.message : "Logout failed",
          ),
        );
    }
  }

  async refreshToken(req: Request<{}, {}, RefreshTokenInput>, res: Response) {
    try {
      const { refreshToken, tenantId } = req.body;
      const ipAddress = req.ip;
      const userAgent = req.get("User-Agent");

      const result = await this.refreshTokenUseCase.execute({
        refreshToken,
        tenantId,
        ipAddress,
        userAgent,
      });

      res.status(ResponseStatus.OK).json(
        StatusMapping.createResponse(ResponseStatus.OK, {
          user: {
            id: result.user.id,
            email: result.user.email.value,
            roles: result.user.roles,
            status: result.user.status,
          },
          accessToken: result.accessToken,
          refreshToken: result.refreshToken,
        }),
      );
    } catch (error) {
      res
        .status(ResponseStatus.UNAUTHORIZED)
        .json(
          StatusMapping.createErrorResponse(
            ResponseStatus.UNAUTHORIZED,
            error instanceof Error ? error.message : "Token refresh failed",
          ),
        );
    }
  }
}

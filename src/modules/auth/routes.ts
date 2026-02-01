import { Router } from "express";
import { AuthController } from "./controller";
import { loginSchema, logoutSchema, refreshTokenSchema } from "./schemas";
import { validateRequest } from "../../shared/middleware/validation";
import { authenticateToken } from "../../shared/middleware/auth";

const router = Router();
const authController = new AuthController(
  // Dependencies will be injected
  {} as any,
  {} as any,
  {} as any,
);

router.post(
  "/login",
  validateRequest(loginSchema),
  authController.login.bind(authController),
);
router.post(
  "/logout",
  authenticateToken,
  validateRequest(logoutSchema),
  authController.logout.bind(authController),
);
router.post(
  "/refresh",
  validateRequest(refreshTokenSchema),
  authController.refreshToken.bind(authController),
);

export { router as authRoutes };

import { Router } from "express";
import { PoliciesController } from "./controller";
import {
  createPolicySchema,
  updatePolicySchema,
  deletePolicySchema,
  getAllPoliciesSchema,
} from "./schemas";
import { validateRequest } from "../../shared/middleware/validation";
import { authenticateToken } from "../../shared/middleware/auth";

const router = Router();
const policiesController = new PoliciesController(
  // Dependencies will be injected
  {} as any,
  {} as any,
  {} as any,
  {} as any,
);

router.post(
  "/",
  authenticateToken,
  validateRequest(createPolicySchema),
  policiesController.createPolicy.bind(policiesController),
);
router.get(
  "/",
  authenticateToken,
  validateRequest(getAllPoliciesSchema),
  policiesController.getAllPolicies.bind(policiesController),
);
router.put(
  "/:id",
  authenticateToken,
  validateRequest(updatePolicySchema),
  policiesController.updatePolicy.bind(policiesController),
);
router.delete(
  "/:id",
  authenticateToken,
  validateRequest(deletePolicySchema),
  policiesController.deletePolicy.bind(policiesController),
);

export { router as policiesRoutes };

import { Request } from "express";

declare global {
  namespace Express {
    interface Request {
      user?: {
        id: string;
        email: string;
        roles: string[];
        tenantId: string;
      };
      tenantId?: string;
    }
  }
}

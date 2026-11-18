
import type { NextFunction, Request, Response } from "express";
import {
  AUTH_COOKIE,
  GUEST_COOKIE,
  clearAuthCookies,
  parseCookieHeader,
} from "../utils/cookies";
import { verifyToken } from "../utils/jwt";
import { forbidden, unauthorized } from "../utils/errors";
import type {
  AuthContext,
  GuestTokenPayload,
  UserTokenPayload,
} from "../types/auth";

function authFromToken(token: string): AuthContext | null {
  const payload = verifyToken<UserTokenPayload | GuestTokenPayload>(token);

  if (!payload) return null;

  if (payload.role === "user" && payload.sub) {
    const user = payload as UserTokenPayload;

    return {
      role: "user",
      userId: user.sub,
      name: user.name,
      email: user.email,
    };
  }

  if (
    payload.role === "guest" &&
    payload.sub &&
    (payload as GuestTokenPayload).roomId
  ) {
    const guest = payload as GuestTokenPayload;

    return {
      role: "guest",
      guestId: guest.sub,
      name: guest.name,
      roomId: guest.roomId,
    };
  }

  return null;
}

/**
 * Reads authentication from cookies first,
 * then falls back to Authorization: Bearer.
 * Never rejects the request.
 */
export function attachAuth(
  req: Request,
  _res: Response,
  next: NextFunction,
): void {
  const header = req.headers.cookie;

  if (header) {
    const cookies = parseCookieHeader(header);

    const userToken = cookies[AUTH_COOKIE];
    if (userToken) {
      const auth = authFromToken(userToken);

      if (auth) {
        req.auth = auth;
        return next();
      }
    }

    const guestToken = cookies[GUEST_COOKIE];
    if (guestToken) {
      const auth = authFromToken(guestToken);

      if (auth) {
        req.auth = auth;
        return next();
      }
    }
  }

  const authorization = req.headers.authorization;

  if (authorization) {
    const match = authorization.match(/^Bearer\s+(.+)$/i);

    if (match) {
      const auth = authFromToken(match[1].trim());

      if (auth) {
        req.auth = auth;
      }
    }
  }

  next();
}

export function requireAuth(
  req: Request,
  res: Response,
  next: NextFunction,
): void {
  if (!req.auth) {
    clearAuthCookies(res);
    return next(unauthorized());
  }

  next();
}

export function requireUser(
  req: Request,
  _res: Response,
  next: NextFunction,
): void {
  if (!req.auth) return next(unauthorized());

  if (req.auth.role !== "user") {
    return next(forbidden("Create an account to access this feature"));
  }

  next();
}

export function currentAuth(req: Request): AuthContext {
  if (!req.auth) throw unauthorized();

  return req.auth;
}

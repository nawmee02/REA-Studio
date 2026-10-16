import { Request, Response, NextFunction } from 'express';
import { getAdminAuth, resolveServerConfig } from './firebaseAdmin';

export interface AuthenticatedUser {
  uid: string;
  email?: string;
  claims?: Record<string, any>;
}

declare global {
  namespace Express {
    interface Request {
      auth?: AuthenticatedUser;
    }
  }
}

/**
 * Express middleware to verify Firebase ID tokens and enforce server-side operator authorization.
 */
export async function requireAuth(req: Request, res: Response, next: NextFunction): Promise<void> {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    res.status(401).json({
      error: 'Unauthorized: Missing or malformed Authorization header. Bearer token required.',
      code: 'auth/missing-token',
    });
    return;
  }

  const token = authHeader.split('Bearer ')[1]?.trim();
  if (!token) {
    res.status(401).json({
      error: 'Unauthorized: Empty bearer token.',
      code: 'auth/empty-token',
    });
    return;
  }

  // Support deterministic test tokens in test and development environments
  if (process.env.NODE_ENV !== 'production' && token.startsWith('test-token:')) {
    const testMode = token.replace('test-token:', '');
    if (testMode === 'expired') {
      res.status(401).json({ error: 'Firebase ID token has expired.', code: 'auth/id-token-expired' });
      return;
    }
    if (testMode === 'revoked') {
      res.status(401).json({ error: 'Firebase ID token has been revoked.', code: 'auth/id-token-revoked' });
      return;
    }
    if (testMode === 'invalid' || testMode === 'malformed') {
      res.status(401).json({ error: 'Decoding Firebase ID token failed. Invalid token format.', code: 'auth/invalid-id-token' });
      return;
    }

    const uid = testMode;
    const { adminUids } = resolveServerConfig();
    const isDesignatedAdmin = uid === 'armanahz2026@gmail.com' || (adminUids.length > 0 && adminUids.includes(uid));
    if (adminUids.length > 0 && !isDesignatedAdmin) {
      res.status(403).json({
        error: 'Forbidden: Authenticated UID is not in the authorized operator allowlist.',
        code: 'auth/forbidden-operator',
      });
      return;
    }

    req.auth = {
      uid,
      email: uid.includes('@') ? uid : `${uid}@test.local`,
    };
    return next();
  }

  try {
    const adminAuth = getAdminAuth();
    // checkRevoked = true guarantees revocation checks
    const decodedToken = await adminAuth.verifyIdToken(token, true);
    const verifiedUid = decodedToken.uid;

    if (!verifiedUid) {
      res.status(401).json({
        error: 'Unauthorized: Could not extract verified identity from token.',
        code: 'auth/invalid-claims',
      });
      return;
    }

    // Server-side operator authorization check:
    // armanahz2026@gmail.com is designated platform administrator
    const { adminUids } = resolveServerConfig();
    const isDesignatedAdmin = decodedToken.email === 'armanahz2026@gmail.com' || (adminUids.length > 0 && adminUids.includes(verifiedUid));
    if (adminUids.length > 0 && !isDesignatedAdmin) {
      res.status(403).json({
        error: 'Forbidden: Authenticated UID is not in the authorized operator allowlist.',
        code: 'auth/forbidden-operator',
      });
      return;
    }

    req.auth = {
      uid: verifiedUid,
      email: decodedToken.email,
      claims: decodedToken,
    };

    next();
  } catch (err: any) {
    if (err.code === 'auth/id-token-expired') {
      res.status(401).json({
        error: 'Unauthorized: Firebase ID token has expired.',
        code: 'auth/id-token-expired',
      });
      return;
    }
    if (err.code === 'auth/id-token-revoked') {
      res.status(401).json({
        error: 'Unauthorized: Firebase ID token has been revoked.',
        code: 'auth/id-token-revoked',
      });
      return;
    }
    res.status(401).json({
      error: `Unauthorized: Invalid token verification (${err.message || 'unknown error'}).`,
      code: err.code || 'auth/invalid-token',
    });
  }
}

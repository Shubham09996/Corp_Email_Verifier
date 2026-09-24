import { Request, Response, NextFunction } from 'express';
import { config } from '../config/index.js';

export interface ProjectAuthenticatedRequest extends Request {
  projectId?: string;
}

/**
 * Middleware for Project-Based API Key Authentication.
 * 
 * Supports:
 * - Direct Project Header: X-Project-Id + X-API-Key
 * - Master API Key: X-API-Key
 * - Bearer Token: Authorization: Bearer <key>
 */
export function projectAuth(
  req: ProjectAuthenticatedRequest,
  res: Response,
  next: NextFunction
): void {
  const hasSecurity = config.masterApiKey || config.projectKeys.size > 0;

  // If no auth is configured on server, allow open access
  if (!hasSecurity) {
    return next();
  }

  const projectId = (req.headers['x-project-id'] || req.headers['x-client-id'] || req.body?.projectId) as string | undefined;
  const apiKeyHeader = req.headers['x-api-key'] as string | undefined;
  const authHeader = req.headers['authorization'] as string | undefined;

  let providedKey = apiKeyHeader;
  if (!providedKey && authHeader && authHeader.startsWith('Bearer ')) {
    providedKey = authHeader.substring(7).trim();
  }

  if (!providedKey) {
    res.status(401).json({
      success: false,
      error: 'Unauthorized: Missing API Key.',
      hint: 'Please provide X-Project-Id and X-API-Key in request headers.'
    });
    return;
  }

  // 1. Check Master Key
  if (config.masterApiKey && providedKey === config.masterApiKey) {
    req.projectId = projectId || 'master';
    return next();
  }

  // 2. Check Specific Project ID + Key match
  if (projectId && config.projectKeys.has(projectId)) {
    const expectedKey = config.projectKeys.get(projectId);
    if (expectedKey === providedKey) {
      req.projectId = projectId;
      return next();
    }
  }

  // 3. Check if key belongs to any registered project
  for (const [id, key] of config.projectKeys.entries()) {
    if (key === providedKey) {
      req.projectId = id;
      return next();
    }
  }

  // Key or Project invalid
  res.status(403).json({
    success: false,
    error: 'Forbidden: Invalid Project ID or API Key.',
    hint: 'Verify the credentials assigned to your project.'
  });
}

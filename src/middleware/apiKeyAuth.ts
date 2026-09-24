import { Request, Response, NextFunction } from 'express';
import { config } from '../config/index.js';

export interface ProjectAuthenticatedRequest extends Request {
  projectId?: string;
}

/**
 * Middleware for Project-Based API Key Authentication.
 * 
 * Supports:
 * - JSON Body: { "api_key": "...", "client_id": "..." } or { "apiKey": "...", "projectId": "..." }
 * - Headers: X-Project-Id (or X-Client-Id) + X-API-Key
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

  // Extract Project/Client ID from Body or Headers
  const projectId = (
    req.body?.client_id ||
    req.body?.clientId ||
    req.body?.project_id ||
    req.body?.projectId ||
    req.headers['x-project-id'] ||
    req.headers['x-client-id']
  ) as string | undefined;

  // Extract API Key from Body or Headers
  let providedKey = (
    req.body?.api_key ||
    req.body?.apiKey ||
    req.headers['x-api-key']
  ) as string | undefined;

  const authHeader = req.headers['authorization'] as string | undefined;
  if (!providedKey && authHeader && authHeader.startsWith('Bearer ')) {
    providedKey = authHeader.substring(7).trim();
  }

  if (!providedKey) {
    res.status(401).json({
      success: false,
      error: 'Unauthorized: Missing API Key.',
      hint: 'Please provide api_key in request body or X-API-Key in request headers.'
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

  // 3. Check if key matches any registered project in pool
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

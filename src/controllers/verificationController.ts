import { Response } from 'express';
import { ProjectAuthenticatedRequest } from '../middleware/apiKeyAuth.js';
import { verifyEmail, verifyEmailBatch } from '../services/emailVerificationService.js';
import { getDomainAge } from '../services/domainAgeService.js';

export async function handleVerifySingleEmail(
  req: ProjectAuthenticatedRequest,
  res: Response
): Promise<void> {
  const email = (req.body?.email || req.query?.email) as string | undefined;
  const projectId = req.projectId || req.body?.projectId || req.headers['x-project-id'];
  const referenceId = req.body?.referenceId || req.body?.customReferenceId;
  const options = req.body?.options || {};

  if (!email || typeof email !== 'string') {
    res.status(400).json({
      success: false,
      error: 'Missing required field: "email".'
    });
    return;
  }

  try {
    const result = await verifyEmail(email, options);

    res.json({
      success: true,
      ...(projectId && { projectId }),
      ...(referenceId && { referenceId }),
      data: result
    });
  } catch (error: any) {
    res.status(500).json({
      success: false,
      error: error.message || 'Failed to verify email.'
    });
  }
}

export async function handleVerifyBatchEmails(
  req: ProjectAuthenticatedRequest,
  res: Response
): Promise<void> {
  const emails = req.body?.emails as string[] | undefined;
  const projectId = req.projectId || req.body?.projectId || req.headers['x-project-id'];
  const options = req.body?.options || {};
  const concurrency = parseInt(req.body?.concurrency || '5', 10);

  if (!emails || !Array.isArray(emails) || emails.length === 0) {
    res.status(400).json({
      success: false,
      error: 'Missing or invalid required field: "emails" (must be a non-empty array of strings).'
    });
    return;
  }

  if (emails.length > 200) {
    res.status(400).json({
      success: false,
      error: 'Batch size exceeds maximum limit of 200 emails per request.'
    });
    return;
  }

  try {
    const batchResult = await verifyEmailBatch(emails, options, concurrency);

    res.json({
      success: true,
      ...(projectId && { projectId }),
      data: batchResult
    });
  } catch (error: any) {
    res.status(500).json({
      success: false,
      error: error.message || 'Failed to process batch verification.'
    });
  }
}

export async function handleDomainAge(
  req: ProjectAuthenticatedRequest,
  res: Response
): Promise<void> {
  let domain = (req.body?.domain || req.params?.domain || req.query?.domain) as string | undefined;
  const projectId = req.projectId || req.body?.projectId || req.headers['x-project-id'];

  // Support passing email instead of domain
  if (!domain && req.body?.email) {
    const parts = (req.body.email as string).split('@');
    if (parts.length > 1) domain = parts[1];
  }

  if (!domain || typeof domain !== 'string') {
    res.status(400).json({
      success: false,
      error: 'Missing required parameter: "domain".'
    });
    return;
  }

  try {
    const cleanDomain = domain.toLowerCase().trim().replace(/^(https?:\/\/)?(www\.)?/, '').split('/')[0];
    const ageResult = await getDomainAge(cleanDomain);

    res.json({
      success: true,
      ...(projectId && { projectId }),
      data: {
        domain: ageResult.domain,
        creationDate: ageResult.creationDate,
        ageYears: ageResult.ageYears,
        ageDays: ageResult.ageDays,
        isNewDomain: ageResult.isNewDomain,
        registrar: ageResult.registrar,
        status: ageResult.domainStatus,
        source: ageResult.source
      }
    });
  } catch (error: any) {
    res.status(500).json({
      success: false,
      error: error.message || 'Failed to resolve domain age.'
    });
  }
}

export function handleHealthCheck(
  req: ProjectAuthenticatedRequest,
  res: Response
): void {
  res.json({
    status: 'healthy',
    service: 'Email Verification API',
    uptimeSeconds: Math.floor(process.uptime()),
    timestamp: new Date().toISOString(),
    nodeVersion: process.version,
    memoryUsageMb: Math.round(process.memoryUsage().rss / (1024 * 1024))
  });
}

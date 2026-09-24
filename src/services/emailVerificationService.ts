import {
  VerificationResult,
  VerificationStatus,
  EmailVerificationOptions,
  BatchVerificationResult
} from '../types/index.js';
import { validateSyntax } from './syntaxValidator.js';
import { resolveMxRecords } from './dnsResolver.js';
import { verifySmtpMailbox } from './smtpVerifier.js';
import { getDomainAge } from './domainAgeService.js';

/**
 * Full 5-Phase Email Verification Pipeline
 */
export async function verifyEmail(
  email: string,
  options: EmailVerificationOptions = {}
): Promise<VerificationResult> {
  const startTime = Date.now();
  const {
    checkSmtp = true,
    checkDomainAge = true,
    allowFreeDomains = false,
    smtpTimeoutMs,
    customHelo,
    customMailFrom
  } = options;

  // Phase 1: Syntax & Banned/Disposable Filter
  const syntaxResult = validateSyntax(email, allowFreeDomains);
  if (!syntaxResult.isValid) {
    let reason = syntaxResult.error || 'Invalid email format';
    let status: VerificationStatus = 'INVALID';
    let score = 0;

    if (syntaxResult.isBannedFreeDomain) {
      reason = 'Personal email domain (Gmail, Yahoo, Outlook, etc.) is not allowed for corporate email.';
      score = 15;
    } else if (syntaxResult.isDisposableDomain) {
      reason = 'Disposable / temporary email domain is not permitted.';
      score = 0;
    }

    return {
      email: syntaxResult.cleanEmail || email,
      status,
      reason,
      score,
      isDeliverable: false,
      isCorporate: !syntaxResult.isBannedFreeDomain && !syntaxResult.isDisposableDomain,
      isCatchAll: false,
      isProtected: false,
      details: {
        syntax: syntaxResult,
        dns: {
          hasMxRecords: false,
          mxRecords: [],
          primaryMx: null,
          resolutionSource: 'NONE'
        }
      },
      durationMs: Date.now() - startTime,
      verifiedAt: new Date().toISOString()
    };
  }

  // Phase 2: Multi-Tier DNS & MX Record Lookup
  const dnsResult = await resolveMxRecords(syntaxResult.domain);
  if (!dnsResult.hasMxRecords || !dnsResult.primaryMx) {
    return {
      email: syntaxResult.cleanEmail,
      status: 'INVALID',
      reason: dnsResult.error || `No mail exchange (MX) records found for domain '${syntaxResult.domain}'.`,
      score: 10,
      isDeliverable: false,
      isCorporate: true,
      isCatchAll: false,
      isProtected: false,
      details: {
        syntax: syntaxResult,
        dns: dnsResult
      },
      durationMs: Date.now() - startTime,
      verifiedAt: new Date().toISOString()
    };
  }

  // Phase 3 & Phase 4: Execute SMTP Handshake and Domain Age Check in Parallel
  const smtpPromise = checkSmtp
    ? verifySmtpMailbox(syntaxResult.cleanEmail, dnsResult.primaryMx, syntaxResult.domain, {
        heloDomain: customHelo,
        mailFrom: customMailFrom,
        timeoutMs: smtpTimeoutMs
      })
    : Promise.resolve(undefined);

  const domainAgePromise = checkDomainAge
    ? getDomainAge(syntaxResult.domain)
    : Promise.resolve(undefined);

  const [smtpResult, domainAgeResult] = await Promise.all([
    smtpPromise,
    domainAgePromise
  ]);

  // Determine Overall Status & Confidence Score
  let status: VerificationStatus = 'VALID';
  let reason = 'Email address and mailbox confirmed active.';
  let score = 50; // Base score for valid syntax + corporate domain + MX records

  if (domainAgeResult?.ageYears && domainAgeResult.ageYears >= 1) {
    score += 15;
  } else if (domainAgeResult?.ageDays && domainAgeResult.ageDays >= 90) {
    score += 10;
  }

  let isCatchAll = false;
  let isProtected = false;

  if (smtpResult) {
    status = smtpResult.status;
    isCatchAll = smtpResult.isCatchAll;
    isProtected = smtpResult.isProtected;

    switch (smtpResult.status) {
      case 'VALID':
        score += 35;
        reason = 'Mailbox confirmed active via SMTP handshake and probe verification.';
        break;
      case 'CATCH_ALL':
        score += 20;
        reason = 'Domain mail server accepts all recipient addresses (Catch-All configured).';
        break;
      case 'PROTECTED':
        score += 20;
        reason = 'Enterprise spam firewall / security gateway protected (e.g. M365, Proofpoint, Cisco).';
        break;
      case 'INVALID':
        score = Math.min(score, 15);
        reason = smtpResult.error || 'Mailbox rejected by mail server (User unknown / not found).';
        break;
    }
  } else {
    // If SMTP check was bypassed
    score += 25;
    reason = 'Domain MX records validated (SMTP probe skipped).';
  }

  score = Math.min(100, Math.max(0, score));
  const isDeliverable = status === 'VALID' || status === 'CATCH_ALL' || status === 'PROTECTED';

  return {
    email: syntaxResult.cleanEmail,
    status,
    reason,
    score,
    isDeliverable,
    isCorporate: !syntaxResult.isBannedFreeDomain && !syntaxResult.isDisposableDomain,
    isCatchAll,
    isProtected,
    details: {
      syntax: syntaxResult,
      dns: dnsResult,
      smtp: smtpResult,
      domainAge: domainAgeResult
    },
    durationMs: Date.now() - startTime,
    verifiedAt: new Date().toISOString()
  };
}

/**
 * Batch Email Verification with controlled concurrency
 */
export async function verifyEmailBatch(
  emails: string[],
  options: EmailVerificationOptions = {},
  concurrency = 5
): Promise<BatchVerificationResult> {
  const startTime = Date.now();
  const results: VerificationResult[] = [];

  // Filter unique non-empty strings
  const cleanList = Array.from(new Set(emails.map(e => (typeof e === 'string' ? e.trim() : '')).filter(Boolean)));

  // Concurrency worker queue
  let currentIndex = 0;
  async function worker() {
    while (currentIndex < cleanList.length) {
      const idx = currentIndex++;
      const email = cleanList[idx];
      try {
        const res = await verifyEmail(email, options);
        results[idx] = res;
      } catch (err: any) {
        results[idx] = {
          email,
          status: 'INVALID',
          reason: `Verification failed: ${err.message}`,
          score: 0,
          isDeliverable: false,
          isCorporate: false,
          isCatchAll: false,
          isProtected: false,
          details: {
            syntax: validateSyntax(email, options.allowFreeDomains),
            dns: { hasMxRecords: false, mxRecords: [], primaryMx: null, resolutionSource: 'NONE' }
          },
          durationMs: 0,
          verifiedAt: new Date().toISOString()
        };
      }
    }
  }

  const workers = Array.from({ length: Math.min(concurrency, cleanList.length) }, () => worker());
  await Promise.all(workers);

  const validCount = results.filter(r => r.status === 'VALID').length;
  const invalidCount = results.filter(r => r.status === 'INVALID').length;
  const catchAllCount = results.filter(r => r.status === 'CATCH_ALL').length;
  const protectedCount = results.filter(r => r.status === 'PROTECTED').length;

  return {
    total: results.length,
    validCount,
    invalidCount,
    catchAllCount,
    protectedCount,
    durationMs: Date.now() - startTime,
    results
  };
}

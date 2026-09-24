import {
  VerificationResult,
  VerificationStatus,
  EmailVerificationOptions,
  BatchVerificationResult
} from '../types/index.js';
import { validateSyntax } from './syntaxValidator.js';
import { isSuspiciousUsername } from './entropyValidator.js';
import { resolveDnsDetails } from './dnsResolver.js';
import { verifySmtpWithFallback } from './smtpVerifier.js';

/**
 * Enterprise Email Verification Pipeline
 */
export async function verifyEmail(
  email: string,
  options: EmailVerificationOptions = {}
): Promise<VerificationResult> {
  const startTime = Date.now();
  const {
    checkSmtp = true,
    allowFreeDomains = false,
    smtpTimeoutMs
  } = options;

  // Phase 1: RFC Syntax & Disposable/Free Domain Filter
  const syntaxResult = validateSyntax(email, allowFreeDomains);
  if (!syntaxResult.isValid) {
    let reason = syntaxResult.error || 'Invalid email format.';
    let score = 0;

    if (syntaxResult.isBannedFreeDomain) {
      reason = 'Personal email domain (Gmail, Yahoo, Outlook, etc.) is not allowed for corporate email.';
      score = 15;
    } else if (syntaxResult.isDisposableDomain) {
      reason = 'Disposable / temporary email domain is not permitted.';
      score = 0;
    }

    return {
      email: syntaxResult.cleanEmail || (typeof email === 'string' ? email.trim() : ''),
      status: 'INVALID',
      reason,
      score,
      isDeliverable: false,
      isCorporate: !syntaxResult.isBannedFreeDomain && !syntaxResult.isDisposableDomain,
      isCatchAll: false,
      isProtected: false,
      isRoleAccount: syntaxResult.isRoleAccount,
      isDisposable: syntaxResult.isDisposableDomain,
      mailProvider: 'None',
      didYouMean: syntaxResult.didYouMean,
      details: {
        syntax: syntaxResult,
        dns: {
          hasMxRecords: false,
          mxRecords: [],
          primaryMx: null,
          mailProvider: 'None',
          hasSpf: false,
          hasDmarc: false,
          resolutionSource: 'NONE'
        }
      },
      durationMs: Date.now() - startTime,
      verifiedAt: new Date().toISOString()
    };
  }

  // Phase 1.5: Synthetic / Dummy / Keyboard-Smash Pattern Detection
  const suspiciousCheck = isSuspiciousUsername(syntaxResult.user);
  if (suspiciousCheck.isSuspicious) {
    return {
      email: syntaxResult.cleanEmail,
      status: 'INVALID',
      reason: suspiciousCheck.reason || 'Synthetic or dummy username pattern detected.',
      score: 0,
      isDeliverable: false,
      isCorporate: true,
      isCatchAll: false,
      isProtected: false,
      isRoleAccount: syntaxResult.isRoleAccount,
      isDisposable: false,
      mailProvider: 'None',
      didYouMean: syntaxResult.didYouMean,
      details: {
        syntax: syntaxResult,
        dns: {
          hasMxRecords: false,
          mxRecords: [],
          primaryMx: null,
          mailProvider: 'None',
          hasSpf: false,
          hasDmarc: false,
          resolutionSource: 'NONE'
        }
      },
      durationMs: Date.now() - startTime,
      verifiedAt: new Date().toISOString()
    };
  }

  // Phase 2: Multi-Tier DNS & MX Resolution with SPF & DMARC
  const dnsResult = await resolveDnsDetails(syntaxResult.domain);
  if (!dnsResult.hasMxRecords || dnsResult.mxRecords.length === 0) {
    return {
      email: syntaxResult.cleanEmail,
      status: 'INVALID',
      reason: dnsResult.error || `No mail exchange (MX) records found for domain '${syntaxResult.domain}'.`,
      score: 0,
      isDeliverable: false,
      isCorporate: true,
      isCatchAll: false,
      isProtected: false,
      isRoleAccount: syntaxResult.isRoleAccount,
      isDisposable: false,
      mailProvider: 'None',
      didYouMean: syntaxResult.didYouMean,
      details: {
        syntax: syntaxResult,
        dns: dnsResult
      },
      durationMs: Date.now() - startTime,
      verifiedAt: new Date().toISOString()
    };
  }

  // Phase 3: Real-Time SMTP Handshake on Port 25
  let smtpResult = undefined;
  if (checkSmtp) {
    smtpResult = await verifySmtpWithFallback(
      syntaxResult.cleanEmail,
      dnsResult.mxRecords,
      syntaxResult.domain,
      { timeoutMs: smtpTimeoutMs }
    );
  }

  // Phase 4: Precision Status Evaluation
  let status: VerificationStatus = 'VALID';
  let reason = 'Corporate mailbox confirmed active and deliverable.';
  let score = 50;

  if (dnsResult.hasSpf) score += 10;
  if (dnsResult.hasDmarc) score += 10;

  let isCatchAll = false;
  let isProtected = false;

  if (smtpResult) {
    status = smtpResult.status;
    isCatchAll = smtpResult.isCatchAll;
    isProtected = smtpResult.isProtected;

    switch (smtpResult.status) {
      case 'VALID':
        score += 30;
        reason = 'Mailbox confirmed active via real-time SMTP handshake.';
        break;
      case 'CATCH_ALL':
        score += 15;
        reason = 'Domain mail server accepts all recipient addresses (Catch-All configured).';
        break;
      case 'PROTECTED':
        score += 15;
        reason = smtpResult.error === 'HOST_PORT25_BLOCKED'
          ? `Corporate mail infrastructure active (${dnsResult.mailProvider}); direct SMTP probing restricted.`
          : `Enterprise spam firewall protected (${dnsResult.mailProvider}).`;
        break;
      case 'INVALID':
        score = 0;
        reason = smtpResult.error || 'Mailbox rejected by mail server (User not found).';
        break;
    }
  } else {
    score += 20;
    reason = 'Domain MX and security records validated.';
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
    isRoleAccount: syntaxResult.isRoleAccount,
    isDisposable: syntaxResult.isDisposableDomain,
    mailProvider: dnsResult.mailProvider,
    didYouMean: syntaxResult.didYouMean,
    details: {
      syntax: syntaxResult,
      dns: dnsResult,
      smtp: smtpResult
    },
    durationMs: Date.now() - startTime,
    verifiedAt: new Date().toISOString()
  };
}

/**
 * Batch Email Verification with Concurrency Control
 */
export async function verifyEmailBatch(
  emails: string[],
  options: EmailVerificationOptions = {},
  concurrency = 5
): Promise<BatchVerificationResult> {
  const startTime = Date.now();
  const results: VerificationResult[] = [];

  const cleanList = Array.from(new Set(emails.map(e => (typeof e === 'string' ? e.trim() : '')).filter(Boolean)));

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
          reason: `Verification error: ${err.message}`,
          score: 0,
          isDeliverable: false,
          isCorporate: false,
          isCatchAll: false,
          isProtected: false,
          isRoleAccount: false,
          isDisposable: false,
          mailProvider: 'None',
          didYouMean: null,
          details: {
            syntax: validateSyntax(email, options.allowFreeDomains),
            dns: {
              hasMxRecords: false,
              mxRecords: [],
              primaryMx: null,
              mailProvider: 'None',
              hasSpf: false,
              hasDmarc: false,
              resolutionSource: 'NONE'
            }
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

export type VerificationStatus = 'VALID' | 'CATCH_ALL' | 'PROTECTED' | 'INVALID';

export type InvalidReason =
  | 'INVALID_SYNTAX'
  | 'BANNED_FREE_EMAIL'
  | 'DISPOSABLE_EMAIL'
  | 'NO_MX_RECORDS'
  | 'MAILBOX_NOT_FOUND'
  | 'DOMAIN_NOT_FOUND'
  | 'CONNECTION_FAILED'
  | 'UNRESOLVED';

export interface MxRecord {
  exchange: string;
  priority: number;
}

export interface SyntaxCheckResult {
  isValid: boolean;
  isBannedFreeDomain: boolean;
  isDisposableDomain: boolean;
  cleanEmail: string;
  user: string;
  domain: string;
  error?: string;
}

export interface DnsCheckResult {
  hasMxRecords: boolean;
  mxRecords: MxRecord[];
  primaryMx: string | null;
  resolutionSource: 'NATIVE_DNS' | 'GOOGLE_DOH' | 'CLOUDFLARE_DOH' | 'NONE';
  error?: string;
}

export interface SmtpCheckResult {
  status: VerificationStatus;
  mailboxExists: boolean;
  isCatchAll: boolean;
  isProtected: boolean;
  responseCode?: number;
  serverMessage?: string;
  targetProbeResponse?: string;
  catchAllProbeResponse?: string;
  connectedHost?: string;
  handshakeSuccess: boolean;
  error?: string;
}

export interface DomainAgeResult {
  domain: string;
  creationDate: string | null;
  ageDays: number | null;
  ageYears: number | null;
  registrar: string | null;
  isNewDomain: boolean; // < 90 days
  domainStatus?: string[];
  source: 'RDAP' | 'WHOIS' | 'CACHE' | 'UNAVAILABLE';
}

export interface EmailVerificationOptions {
  checkSmtp?: boolean;
  checkDomainAge?: boolean;
  allowFreeDomains?: boolean;
  smtpTimeoutMs?: number;
  customHelo?: string;
  customMailFrom?: string;
}

export interface VerificationResult {
  email: string;
  status: VerificationStatus;
  reason?: string;
  score: number; // 0 to 100 confidence score
  isDeliverable: boolean;
  isCorporate: boolean;
  isCatchAll: boolean;
  isProtected: boolean;
  details: {
    syntax: SyntaxCheckResult;
    dns: DnsCheckResult;
    smtp?: SmtpCheckResult;
    domainAge?: DomainAgeResult;
  };
  durationMs: number;
  verifiedAt: string;
}

export interface BatchVerificationResult {
  total: number;
  validCount: number;
  invalidCount: number;
  catchAllCount: number;
  protectedCount: number;
  durationMs: number;
  results: VerificationResult[];
}

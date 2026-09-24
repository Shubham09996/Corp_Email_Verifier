export type VerificationStatus = 'VALID' | 'INVALID' | 'CATCH_ALL';

export interface MxRecord {
  exchange: string;
  priority: number;
}

export interface SyntaxCheckResult {
  isValid: boolean;
  isBannedFreeDomain: boolean;
  isDisposableDomain: boolean;
  isRoleAccount: boolean;
  cleanEmail: string;
  user: string;
  domain: string;
  didYouMean: string | null;
  error?: string;
}

export interface DnsCheckResult {
  hasMxRecords: boolean;
  mxRecords: MxRecord[];
  primaryMx: string | null;
  mailProvider: string;
  hasSpf: boolean;
  hasDmarc: boolean;
  spfRecord?: string | null;
  dmarcRecord?: string | null;
  resolutionSource: 'NATIVE_DNS' | 'GOOGLE_DOH' | 'CLOUDFLARE_DOH' | 'NONE';
  error?: string;
}

export interface SmtpCheckResult {
  status: VerificationStatus;
  mailboxExists: boolean;
  isCatchAll: boolean;
  responseCode?: number;
  serverMessage?: string;
  targetProbeResponse?: string;
  catchAllProbeResponse?: string;
  connectedHost?: string;
  handshakeSuccess: boolean;
  error?: string;
}

export interface EmailVerificationOptions {
  checkSmtp?: boolean;
  allowFreeDomains?: boolean;
  checkDnsSecurity?: boolean;
  smtpTimeoutMs?: number;
}

export interface VerificationResult {
  email: string;
  status: VerificationStatus;
  reason: string;
  score: number; // 0 to 100 confidence score
  isDeliverable: boolean;
  isCorporate: boolean;
  isCatchAll: boolean;
  isRoleAccount: boolean;
  isDisposable: boolean;
  mailProvider: string;
  didYouMean: string | null;
  details: {
    syntax: SyntaxCheckResult;
    dns: DnsCheckResult;
    smtp?: SmtpCheckResult;
  };
  durationMs: number;
  verifiedAt: string;
}

export interface BatchVerificationResult {
  total: number;
  validCount: number;
  invalidCount: number;
  catchAllCount: number;
  durationMs: number;
  results: VerificationResult[];
}

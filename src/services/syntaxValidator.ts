import { SyntaxCheckResult } from '../types/index.js';
import { isBannedFreeDomain, isDisposableDomain } from '../constants/bannedDomains.js';

// Standard RFC 5322 compatible regex check
const EMAIL_REGEX = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/;

export function validateSyntax(
  email: unknown,
  allowFreeDomains = false
): SyntaxCheckResult {
  if (!email || typeof email !== 'string' || !email.trim()) {
    return {
      isValid: false,
      isBannedFreeDomain: false,
      isDisposableDomain: false,
      cleanEmail: '',
      user: '',
      domain: '',
      error: 'Official work / company email is required.'
    };
  }

  const cleanEmail = email.trim().toLowerCase();

  // Basic length checks according to RFC specifications
  if (cleanEmail.length > 254) {
    return {
      isValid: false,
      isBannedFreeDomain: false,
      isDisposableDomain: false,
      cleanEmail,
      user: '',
      domain: '',
      error: 'Email address exceeds maximum allowed length (254 characters).'
    };
  }

  const atIndex = cleanEmail.lastIndexOf('@');
  if (atIndex === -1 || atIndex === 0 || atIndex === cleanEmail.length - 1) {
    return {
      isValid: false,
      isBannedFreeDomain: false,
      isDisposableDomain: false,
      cleanEmail,
      user: '',
      domain: '',
      error: 'Please provide a valid official corporate email address.'
    };
  }

  const user = cleanEmail.substring(0, atIndex);
  const domain = cleanEmail.substring(atIndex + 1);

  if (user.length > 64) {
    return {
      isValid: false,
      isBannedFreeDomain: false,
      isDisposableDomain: false,
      cleanEmail,
      user,
      domain,
      error: 'Email username exceeds maximum allowed length (64 characters).'
    };
  }

  if (!EMAIL_REGEX.test(cleanEmail)) {
    return {
      isValid: false,
      isBannedFreeDomain: false,
      isDisposableDomain: false,
      cleanEmail,
      user,
      domain,
      error: 'Please provide a valid official corporate email address.'
    };
  }

  // Check for consecutive dots
  if (cleanEmail.includes('..')) {
    return {
      isValid: false,
      isBannedFreeDomain: false,
      isDisposableDomain: false,
      cleanEmail,
      user,
      domain,
      error: 'Email address contains invalid consecutive dots.'
    };
  }

  // Check domain TLD length
  const domainParts = domain.split('.');
  if (domainParts.length < 2 || domainParts[domainParts.length - 1].length < 2) {
    return {
      isValid: false,
      isBannedFreeDomain: false,
      isDisposableDomain: false,
      cleanEmail,
      user,
      domain,
      error: 'Domain does not have a valid top-level domain (TLD).'
    };
  }

  const isBanned = isBannedFreeDomain(domain);
  const isDisposable = isDisposableDomain(domain);

  if (!allowFreeDomains && isBanned) {
    return {
      isValid: false,
      isBannedFreeDomain: true,
      isDisposableDomain: isDisposable,
      cleanEmail,
      user,
      domain,
      error: 'Personal email domains (Gmail, Yahoo, Outlook, etc.) are not allowed for official email. Please provide your official company/work email.'
    };
  }

  if (isDisposable) {
    return {
      isValid: false,
      isBannedFreeDomain: isBanned,
      isDisposableDomain: true,
      cleanEmail,
      user,
      domain,
      error: 'Disposable / temporary email addresses are not permitted.'
    };
  }

  return {
    isValid: true,
    isBannedFreeDomain: isBanned,
    isDisposableDomain: isDisposable,
    cleanEmail,
    user,
    domain
  };
}

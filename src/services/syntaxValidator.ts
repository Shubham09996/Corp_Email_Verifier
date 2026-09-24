import { SyntaxCheckResult } from '../types/index.js';
import {
  isBannedFreeDomain,
  isDisposableDomain,
  isRoleAccount,
  checkDomainTypo
} from '../constants/bannedDomains.js';

// RFC 5322 standard regex
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
      isRoleAccount: false,
      cleanEmail: '',
      user: '',
      domain: '',
      didYouMean: null,
      error: 'Official corporate email address is required.'
    };
  }

  const cleanEmail = email.trim().toLowerCase();

  // Basic length checks
  if (cleanEmail.length > 254) {
    return {
      isValid: false,
      isBannedFreeDomain: false,
      isDisposableDomain: false,
      isRoleAccount: false,
      cleanEmail,
      user: '',
      domain: '',
      didYouMean: null,
      error: 'Email address exceeds maximum allowed length (254 characters).'
    };
  }

  const atIndex = cleanEmail.lastIndexOf('@');
  if (atIndex === -1 || atIndex === 0 || atIndex === cleanEmail.length - 1) {
    return {
      isValid: false,
      isBannedFreeDomain: false,
      isDisposableDomain: false,
      isRoleAccount: false,
      cleanEmail,
      user: '',
      domain: '',
      didYouMean: null,
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
      isRoleAccount: false,
      cleanEmail,
      user,
      domain,
      didYouMean: null,
      error: 'Email username exceeds maximum allowed length (64 characters).'
    };
  }

  // Regex check
  if (!EMAIL_REGEX.test(cleanEmail)) {
    return {
      isValid: false,
      isBannedFreeDomain: false,
      isDisposableDomain: false,
      isRoleAccount: false,
      cleanEmail,
      user,
      domain,
      didYouMean: null,
      error: 'Please provide a valid official corporate email address.'
    };
  }

  // Consecutive dots or invalid dots
  if (cleanEmail.includes('..') || user.startsWith('.') || user.endsWith('.')) {
    return {
      isValid: false,
      isBannedFreeDomain: false,
      isDisposableDomain: false,
      isRoleAccount: false,
      cleanEmail,
      user,
      domain,
      didYouMean: null,
      error: 'Email address contains invalid consecutive or boundary dots.'
    };
  }

  // TLD validation
  const domainParts = domain.split('.');
  if (domainParts.length < 2 || domainParts[domainParts.length - 1].length < 2) {
    return {
      isValid: false,
      isBannedFreeDomain: false,
      isDisposableDomain: false,
      isRoleAccount: false,
      cleanEmail,
      user,
      domain,
      didYouMean: null,
      error: 'Domain does not have a valid top-level domain (TLD).'
    };
  }

  const isBanned = isBannedFreeDomain(domain);
  const isDisposable = isDisposableDomain(domain);
  const isRole = isRoleAccount(user);
  const didYouMean = checkDomainTypo(user, domain);

  if (!allowFreeDomains && isBanned) {
    return {
      isValid: false,
      isBannedFreeDomain: true,
      isDisposableDomain: isDisposable,
      isRoleAccount: isRole,
      cleanEmail,
      user,
      domain,
      didYouMean,
      error: 'Personal email domains (Gmail, Yahoo, Outlook, etc.) are not allowed for corporate email.'
    };
  }

  if (isDisposable) {
    return {
      isValid: false,
      isBannedFreeDomain: isBanned,
      isDisposableDomain: true,
      isRoleAccount: isRole,
      cleanEmail,
      user,
      domain,
      didYouMean,
      error: 'Disposable / temporary email addresses are not permitted.'
    };
  }

  return {
    isValid: true,
    isBannedFreeDomain: isBanned,
    isDisposableDomain: isDisposable,
    isRoleAccount: isRole,
    cleanEmail,
    user,
    domain,
    didYouMean
  };
}

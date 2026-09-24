/**
 * Free / Personal Webmail Domains
 * These are banned when verifying corporate / official work emails.
 */
export const BANNED_FREE_EMAIL_DOMAINS = new Set([
  'gmail.com',
  'googlemail.com',
  'yahoo.com',
  'yahoo.co.in',
  'yahoo.in',
  'yahoo.co.uk',
  'yahoo.fr',
  'yahoo.de',
  'yahoo.es',
  'yahoo.com.br',
  'yahoo.com.au',
  'outlook.com',
  'hotmail.com',
  'hotmail.co.uk',
  'hotmail.fr',
  'live.com',
  'msn.com',
  'rediffmail.com',
  'rediff.com',
  'icloud.com',
  'me.com',
  'mac.com',
  'aol.com',
  'aim.com',
  'proton.me',
  'protonmail.com',
  'protonmail.ch',
  'zoho.com',
  'zohomail.in',
  'gmx.com',
  'gmx.net',
  'gmx.de',
  'mail.com',
  'email.com',
  'usa.com',
  'yandex.com',
  'yandex.ru',
  'tutanota.com',
  'tutamail.com',
  'tuta.com',
  'fastmail.com',
  'hushmail.com',
  'mailfence.com',
  'posteo.net',
  'inbox.com',
  'lycos.com',
  'sbcglobal.net',
  'att.net',
  'verizon.net',
  'comcast.net',
  'cox.net',
  'charter.net',
  'rocketmail.com'
]);

/**
 * Known Disposable / Temporary Email Domains
 */
export const DISPOSABLE_EMAIL_DOMAINS = new Set([
  'tempmail.com',
  'tempmail.net',
  'temp-mail.org',
  '10minutemail.com',
  '10minutemail.net',
  'guerrillamail.com',
  'guerrillamail.net',
  'guerrillamail.org',
  'guerrillamailblock.com',
  'sharklasers.com',
  'grr.la',
  'yopmail.com',
  'yopmail.fr',
  'yopmail.net',
  'mailinator.com',
  'trashmail.com',
  'trashmail.net',
  'getnada.com',
  'abakus.my',
  'dispostable.com',
  'throwawaymail.com',
  'fakeinbox.com',
  'mohmal.com',
  'burnermail.io',
  'maildrop.cc',
  'crazymailing.com',
  'mytemp.email',
  'tempail.com',
  'generator.email',
  'internxt.com',
  'inboxkitten.com',
  'minuteinbox.com',
  'emailondeck.com',
  'tmailor.com',
  'luxusmail.org',
  'clipmail.eu',
  'tempr.email',
  'discard.email',
  'dropmail.me'
]);

export function isBannedFreeDomain(domain: string): boolean {
  const lowerDomain = domain.toLowerCase().trim();
  if (BANNED_FREE_EMAIL_DOMAINS.has(lowerDomain)) return true;
  for (const banned of BANNED_FREE_EMAIL_DOMAINS) {
    if (lowerDomain.endsWith('.' + banned)) return true;
  }
  return false;
}

export function isDisposableDomain(domain: string): boolean {
  const lowerDomain = domain.toLowerCase().trim();
  if (DISPOSABLE_EMAIL_DOMAINS.has(lowerDomain)) return true;
  for (const disp of DISPOSABLE_EMAIL_DOMAINS) {
    if (lowerDomain.endsWith('.' + disp)) return true;
  }
  return false;
}

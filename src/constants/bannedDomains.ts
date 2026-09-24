/**
 * Free / Personal Webmail Domains
 */
export const BANNED_FREE_EMAIL_DOMAINS = new Set([
  'gmail.com', 'googlemail.com', 'yahoo.com', 'yahoo.co.in', 'yahoo.in',
  'yahoo.co.uk', 'yahoo.fr', 'yahoo.de', 'yahoo.es', 'yahoo.com.br',
  'yahoo.com.au', 'yahoo.ca', 'outlook.com', 'hotmail.com', 'hotmail.co.uk',
  'hotmail.fr', 'hotmail.de', 'live.com', 'live.co.uk', 'msn.com',
  'rediffmail.com', 'rediff.com', 'icloud.com', 'me.com', 'mac.com',
  'aol.com', 'aim.com', 'proton.me', 'protonmail.com', 'protonmail.ch',
  'zoho.com', 'zohomail.in', 'gmx.com', 'gmx.net', 'gmx.de', 'mail.com',
  'email.com', 'usa.com', 'yandex.com', 'yandex.ru', 'tutanota.com',
  'tutamail.com', 'tuta.com', 'fastmail.com', 'hushmail.com', 'mailfence.com',
  'posteo.net', 'inbox.com', 'lycos.com', 'sbcglobal.net', 'att.net',
  'verizon.net', 'comcast.net', 'cox.net', 'charter.net', 'rocketmail.com',
  'bellsouth.net', 'windstream.net', 'earthlink.net', 'juno.com', 'naver.com',
  'daum.net', 'hanmail.net', 'qq.com', '163.com', '126.com', 'sina.com',
  'sohu.com', 'aliyun.com', 'web.de', 'freenet.de', 't-online.de', 'wanadoo.fr',
  'orange.fr', 'free.fr', 'sfr.fr', 'laposte.net', 'libero.it', 'virgilio.it',
  'alice.it', 'uol.com.br', 'bol.com.br', 'terra.com.br', 'ig.com.br'
]);

/**
 * Known Disposable / Temporary / Burner Email Domains
 */
export const DISPOSABLE_EMAIL_DOMAINS = new Set([
  'tempmail.com', 'tempmail.net', 'temp-mail.org', '10minutemail.com',
  '10minutemail.net', '10minutemail.org', 'guerrillamail.com', 'guerrillamail.net',
  'guerrillamail.org', 'guerrillamail.biz', 'guerrillamailblock.com', 'sharklasers.com',
  'grr.la', 'pokemail.net', 'spam4.me', 'yopmail.com', 'yopmail.fr', 'yopmail.net',
  'cool.fr.nf', 'jetable.fr.nf', 'nospam.ze.tc', 'nomail.xl.cx', 'mega.zik.dj',
  'speed.1s.fr', 'courriel.fr.nf', 'moncourrier.fr.nf', 'monemail.fr.nf', 'monmail.fr.nf',
  'mailinator.com', 'mailinator2.com', 'mailinator.net', 'suremail.info', 'trashmail.com',
  'trashmail.net', 'trashmail.org', 'trashmail.me', 'getnada.com', 'abakus.my',
  'dispostable.com', 'throwawaymail.com', 'fakeinbox.com', 'mohmal.com', 'mohmal.im',
  'mohmal.in', 'burnermail.io', 'maildrop.cc', 'crazymailing.com', 'mytemp.email',
  'tempail.com', 'generator.email', 'internxt.com', 'inboxkitten.com', 'minuteinbox.com',
  'emailondeck.com', 'tmailor.com', 'luxusmail.org', 'clipmail.eu', 'tempr.email',
  'discard.email', 'dropmail.me', 'airmail.news', 'amail.club', 'binkmail.com',
  'bobmail.info', 'chammy.info', 'devnullmail.com', 'dontsendmespam.de', 'drdrb.net',
  'emailigo.de', 'filzmail.com', 'getairmail.com', 'incognitomail.org', 'kasmail.com',
  'mailcatch.com', 'mailnull.com', 'meltmail.com', 'mytrashmail.com', 'nobulk.com',
  'noclickemail.com', 'nonspam.eu', 'notsharingmy.info', 'owlpic.com', 'pookmail.com',
  'safetymail.info', 'sofort-mail.de', 'spambob.com', 'spamex.com', 'spamfree24.org',
  'spamgourmet.com', 'spamhole.com', 'spaml.de', 'tempemail.net', 'trashymail.com',
  'wegwerfmail.de', 'wegwerfmail.net', 'wegwerfmail.org', 'whyspam.me', 'zetmail.com'
]);

/**
 * Role-Based / Generic Accounts (often non-personal corporate mailboxes)
 */
export const ROLE_BASED_PREFIXES = new Set([
  'admin', 'administrator', 'support', 'info', 'sales', 'billing',
  'contact', 'hr', 'careers', 'jobs', 'marketing', 'team', 'help',
  'press', 'media', 'security', 'legal', 'compliance', 'office',
  'hello', 'hi', 'inquiry', 'general', 'postmaster', 'hostmaster',
  'webmaster', 'abuse', 'noc', 'mail', 'finance', 'accounting',
  'invoice', 'dev', 'developer', 'engineering', 'ops', 'operations',
  'null', 'no-reply', 'noreply', 'bounce', 'mailer-daemon', 'privacy',
  'feedback', 'service', 'services', 'order', 'orders', 'enquiry',
  'customer', 'customercare', 'staff', 'reception', 'desk'
]);

/**
 * Common Corporate & Webmail Typos with Corrections
 */
export const COMMON_DOMAIN_TYPOS: Record<string, string> = {
  'gmial.com': 'gmail.com',
  'gmaill.com': 'gmail.com',
  'gamil.com': 'gmail.com',
  'gmai.com': 'gmail.com',
  'gmal.com': 'gmail.com',
  'yaho.com': 'yahoo.com',
  'yahooo.com': 'yahoo.com',
  'yaho.co.in': 'yahoo.co.in',
  'outlok.com': 'outlook.com',
  'outloo.com': 'outlook.com',
  'hotmial.com': 'hotmail.com',
  'hotmaill.com': 'hotmail.com',
  'hotmai.com': 'hotmail.com',
  'iclud.com': 'icloud.com',
  'icoud.com': 'icloud.com',
  'microsft.com': 'microsoft.com',
  'microsof.com': 'microsoft.com',
  'gogle.com': 'google.com',
  'gooogle.com': 'google.com',
  'amazn.com': 'amazon.com',
  'amzon.com': 'amazon.com'
};

export function isBannedFreeDomain(domain: string): boolean {
  const lower = domain.toLowerCase().trim();
  if (BANNED_FREE_EMAIL_DOMAINS.has(lower)) return true;
  for (const banned of BANNED_FREE_EMAIL_DOMAINS) {
    if (lower.endsWith('.' + banned)) return true;
  }
  return false;
}

export function isDisposableDomain(domain: string): boolean {
  const lower = domain.toLowerCase().trim();
  if (DISPOSABLE_EMAIL_DOMAINS.has(lower)) return true;
  for (const disp of DISPOSABLE_EMAIL_DOMAINS) {
    if (lower.endsWith('.' + disp)) return true;
  }
  return false;
}

export function isRoleAccount(user: string): boolean {
  const lower = user.toLowerCase().trim();
  return ROLE_BASED_PREFIXES.has(lower);
}

export function checkDomainTypo(user: string, domain: string): string | null {
  const lowerDomain = domain.toLowerCase().trim();
  if (COMMON_DOMAIN_TYPOS[lowerDomain]) {
    return `${user}@${COMMON_DOMAIN_TYPOS[lowerDomain]}`;
  }
  return null;
}

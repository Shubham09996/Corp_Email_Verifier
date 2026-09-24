/**
 * Detects synthetic, dummy, fake, or keyboard-smash email usernames.
 */

const FAKE_PATTERNS = [
  /^fake[0-9_-]*/i,
  /^test(ing)?[0-9_-]*/i,
  /^dummy[0-9_-]*/i,
  /^sample[0-9_-]*/i,
  /^temp[0-9_-]*/i,
  /^nonexistent[0-9_-]*/i,
  /^asdf(gh|jkl)?[0-9_-]*/i,
  /^qwerty[0-9_-]*/i,
  /^zxcv[0-9_-]*/i,
  /^1234[0-9_-]*/i,
  /^user[0-9]{4,}/i,
  /^abc[0-9]{4,}/i,
  /^null[0-9_-]*/i,
  /^void[0-9_-]*/i,
  /^noemail[0-9_-]*/i,
  /^random[0-9_-]*/i,
  /^example[0-9_-]*/i,
  /^unknown[0-9_-]*/i,
  /^fakeuser/i,
  /^testuser/i,
  /^dummyuser/i
];

const KEYBOARD_SMASH_PATTERNS = [
  /asdfgh/i,
  /qwerty/i,
  /zxcvbn/i,
  /123456/i,
  /654321/i,
  /abcdef/i,
  /qawsed/i,
  /qazwsx/i
];

/**
 * Check if the username exhibits characteristics of a fake, dummy, or keyboard-smash email.
 */
export function isSuspiciousUsername(user: string): { isSuspicious: boolean; reason?: string } {
  const clean = user.toLowerCase().trim();

  // 1. Check known fake prefixes
  for (const pattern of FAKE_PATTERNS) {
    if (pattern.test(clean)) {
      return { isSuspicious: true, reason: 'Synthetic or dummy email pattern detected.' };
    }
  }

  // 2. Check keyboard smash patterns
  for (const pattern of KEYBOARD_SMASH_PATTERNS) {
    if (pattern.test(clean)) {
      return { isSuspicious: true, reason: 'Keyboard smash or sequential pattern detected.' };
    }
  }

  // 3. Check unnatural character repetitions (e.g. aaaaa, 11111)
  if (/(.)\1{4,}/.test(clean)) {
    return { isSuspicious: true, reason: 'Unnatural repetitive character sequence detected.' };
  }

  // 4. Check excessive consonant clusters (e.g. sdfghjkl)
  if (/[bcdfghjklmnpqrstvwxyz]{6,}/i.test(clean)) {
    return { isSuspicious: true, reason: 'High-entropy consonant cluster (gibberish) detected.' };
  }

  // 5. Only numbers of length >= 6 (unless standard phone email format)
  if (/^\d{6,}$/.test(clean)) {
    return { isSuspicious: true, reason: 'Numeric sequence without name pattern.' };
  }

  return { isSuspicious: false };
}

import { validateSyntax } from '../services/syntaxValidator.js';
import { resolveDnsDetails } from '../services/dnsResolver.js';
import { verifyEmail } from '../services/emailVerificationService.js';

async function runAllTests() {
  console.log('====================================================');
  console.log('🧪 Starting Upgraded Email Verification Engine Tests');
  console.log('====================================================\n');

  let passed = 0;
  let failed = 0;

  function assert(condition: boolean, testName: string) {
    if (condition) {
      console.log(`✅ [PASS] ${testName}`);
      passed++;
    } else {
      console.error(`❌ [FAIL] ${testName}`);
      failed++;
    }
  }

  // --- Phase 1: Enhanced Syntax, Typo & Role Accounts ---
  console.log('--- Testing Phase 1: Syntax, Role Accounts & Typos ---');
  
  const p1Valid = validateSyntax('employee@stripe.com');
  assert(p1Valid.isValid && p1Valid.domain === 'stripe.com', 'Valid corporate email passes syntax');

  const p1Role = validateSyntax('support@company.com');
  assert(p1Role.isValid && p1Role.isRoleAccount, 'Role-based account (support@) detected');

  const p1Typo = validateSyntax('john@gmial.com');
  assert(p1Typo.didYouMean === 'john@gmail.com', 'Domain typo (gmial.com -> gmail.com) detected');

  const p1Gmail = validateSyntax('john.doe@gmail.com', false);
  assert(!p1Gmail.isValid && p1Gmail.isBannedFreeDomain, 'Gmail rejected for corporate email');

  const p1Disposable = validateSyntax('temp@yopmail.com');
  assert(!p1Disposable.isValid && p1Disposable.isDisposableDomain, 'Disposable domain rejected');

  // --- Phase 2: DNS, SPF, DMARC & Provider Fingerprinting ---
  console.log('\n--- Testing Phase 2: DNS, SPF, DMARC & Provider Detection ---');
  
  const dnsGoogle = await resolveDnsDetails('google.com');
  assert(dnsGoogle.hasMxRecords && dnsGoogle.mailProvider.includes('Google'), 'Identifies Google Workspace provider');
  console.log(`   google.com Provider: ${dnsGoogle.mailProvider}, SPF: ${dnsGoogle.hasSpf}, DMARC: ${dnsGoogle.hasDmarc}`);

  const dnsMicrosoft = await resolveDnsDetails('microsoft.com');
  assert(dnsMicrosoft.hasMxRecords && dnsMicrosoft.mailProvider.includes('Microsoft'), 'Identifies Microsoft 365 provider');
  console.log(`   microsoft.com Provider: ${dnsMicrosoft.mailProvider}, SPF: ${dnsMicrosoft.hasSpf}, DMARC: ${dnsMicrosoft.hasDmarc}`);

  const dnsFake = await resolveDnsDetails('fake-non-existent-domain-123456789.xyz');
  assert(!dnsFake.hasMxRecords, 'Non-existent domain returns no MX');

  // --- Phase 3 & End-to-End ---
  console.log('\n--- Testing Phase 3: Real-Time Handshake & Pipeline ---');
  
  const resBanned = await verifyEmail('user@gmail.com', { allowFreeDomains: false });
  assert(Boolean(resBanned.status === 'INVALID' && resBanned.reason && resBanned.reason.includes('Personal email')), 'Gmail filtered with reason');

  const resInvalidDomain = await verifyEmail('test@fake-non-existent-domain-123456789.xyz');
  assert(Boolean(resInvalidDomain.status === 'INVALID' && !resInvalidDomain.details.dns.hasMxRecords), 'Fake domain filtered with missing MX');

  const resStripe = await verifyEmail('contact@stripe.com', { checkSmtp: true });
  assert(Boolean(resStripe.isDeliverable && resStripe.isCorporate), 'Stripe corporate email is evaluated');
  console.log(`   contact@stripe.com status: ${resStripe.status}, Provider: ${resStripe.mailProvider}, Score: ${resStripe.score}/100`);

  const resMicrosoft = await verifyEmail('hr@microsoft.com', { checkSmtp: true });
  assert(Boolean(resMicrosoft.isDeliverable && resMicrosoft.mailProvider.includes('Microsoft')), 'Microsoft 365 security evaluated');
  console.log(`   hr@microsoft.com status: ${resMicrosoft.status}, Provider: ${resMicrosoft.mailProvider}, Score: ${resMicrosoft.score}/100`);

  console.log('\n====================================================');
  console.log(`🏁 Test Summary: ${passed} Passed, ${failed} Failed`);
  console.log('====================================================');

  if (failed > 0) {
    process.exit(1);
  }
}

runAllTests().catch((err) => {
  console.error('Test execution failed:', err);
  process.exit(1);
});

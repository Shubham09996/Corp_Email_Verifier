import { validateSyntax } from '../services/syntaxValidator.js';
import { resolveMxRecords } from '../services/dnsResolver.js';
import { verifyEmail } from '../services/emailVerificationService.js';
import { getDomainAge } from '../services/domainAgeService.js';

async function runAllTests() {
  console.log('====================================================');
  console.log('🧪 Starting Automated Email Verification Engine Tests');
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

  // --- Phase 1 Tests: Syntax & Banned Domains ---
  console.log('--- Testing Phase 1: Syntax & Banned Domains ---');
  
  const p1Valid = validateSyntax('employee@stripe.com');
  assert(p1Valid.isValid && p1Valid.domain === 'stripe.com', 'Valid corporate email passes syntax');

  const p1Gmail = validateSyntax('john.doe@gmail.com', false);
  assert(!p1Gmail.isValid && p1Gmail.isBannedFreeDomain, 'Gmail is rejected for corporate email');

  const p1GmailAllowed = validateSyntax('john.doe@gmail.com', true);
  assert(p1GmailAllowed.isValid, 'Gmail is accepted when allowFreeDomains is true');

  const p1Disposable = validateSyntax('temp@yopmail.com');
  assert(!p1Disposable.isValid && p1Disposable.isDisposableDomain, 'Disposable domain is rejected');

  const p1Malformed = validateSyntax('invalid.email@com');
  assert(!p1Malformed.isValid, 'Malformed domain without valid TLD is rejected');

  // --- Phase 2 Tests: Multi-Tier DNS & MX Lookup ---
  console.log('\n--- Testing Phase 2: DNS & MX Lookup ---');
  
  const dnsGoogle = await resolveMxRecords('google.com');
  assert(dnsGoogle.hasMxRecords && dnsGoogle.mxRecords.length > 0, 'Resolves MX records for google.com');
  console.log(`   Found ${dnsGoogle.mxRecords.length} MX records for google.com (Primary: ${dnsGoogle.primaryMx}, Source: ${dnsGoogle.resolutionSource})`);

  const dnsMicrosoft = await resolveMxRecords('microsoft.com');
  assert(dnsMicrosoft.hasMxRecords && dnsMicrosoft.primaryMx !== null, 'Resolves MX records for microsoft.com');

  const dnsFake = await resolveMxRecords('fake-non-existent-domain-123456789.xyz');
  assert(!dnsFake.hasMxRecords, 'Non-existent domain returns no MX records');

  // --- Phase 4 Tests: Domain Age & Corporate Legitimacy ---
  console.log('\n--- Testing Phase 4: Domain Age (WHOIS / RDAP) ---');
  
  const ageGoogle = await getDomainAge('google.com');
  assert(ageGoogle.creationDate !== null && (ageGoogle.ageYears || 0) > 20, 'Google.com domain age > 20 years');
  console.log(`   google.com created on ${ageGoogle.creationDate}, Age: ${ageGoogle.ageYears} years, Registrar: ${ageGoogle.registrar}`);

  const ageStripe = await getDomainAge('stripe.com');
  assert(ageStripe.creationDate !== null && (ageStripe.ageYears || 0) > 10, 'Stripe.com domain age > 10 years');
  console.log(`   stripe.com created on ${ageStripe.creationDate}, Age: ${ageStripe.ageYears} years`);

  // --- End-to-End Pipeline Tests ---
  console.log('\n--- Testing End-to-End 5-Phase Pipeline ---');
  
  const resBanned = await verifyEmail('user@gmail.com', { allowFreeDomains: false });
  assert(Boolean(resBanned.status === 'INVALID' && resBanned.reason && resBanned.reason.includes('Personal email')), 'Gmail filtered out with score and reason');

  const resInvalidDomain = await verifyEmail('test@fake-non-existent-domain-123456789.xyz');
  assert(Boolean(resInvalidDomain.status === 'INVALID' && !resInvalidDomain.details.dns?.hasMxRecords), 'Fake domain filtered with missing MX');

  const resCorp = await verifyEmail('contact@stripe.com', { checkSmtp: true, checkDomainAge: true });
  assert(Boolean(resCorp.isDeliverable && resCorp.isCorporate), 'Stripe corporate email is evaluated with full breakdown');
  console.log(`   contact@stripe.com result status: ${resCorp.status}, Deliverable: ${resCorp.isDeliverable}, Score: ${resCorp.score}/100`);

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

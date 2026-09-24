import { validateSyntax } from '../services/syntaxValidator.js';
import { isSuspiciousUsername } from '../services/entropyValidator.js';
import { resolveDnsDetails } from '../services/dnsResolver.js';
import { verifyEmail } from '../services/emailVerificationService.js';

async function runAllTests() {
  console.log('====================================================');
  console.log('🧪 Starting High-Precision Verification Tests');
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

  // --- Phase 1: Synthetic & Dummy Username Detection ---
  console.log('--- Testing Synthetic & Fake Pattern Detection ---');
  
  const fake1 = isSuspiciousUsername('fake123');
  assert(fake1.isSuspicious, 'Detects fake123 as suspicious');

  const fake2 = isSuspiciousUsername('asdfghjkl');
  assert(fake2.isSuspicious, 'Detects keyboard smash as suspicious');

  const fake3 = isSuspiciousUsername('dummyuser');
  assert(fake3.isSuspicious, 'Detects dummyuser as suspicious');

  const realUser = isSuspiciousUsername('john.doe');
  assert(!realUser.isSuspicious, 'Passes legitimate username john.doe');

  // --- Phase 2: DNS & Security ---
  console.log('\n--- Testing DNS & Provider Fingerprinting ---');
  
  const dnsGoogle = await resolveDnsDetails('google.com');
  assert(dnsGoogle.hasMxRecords && dnsGoogle.mailProvider.includes('Google'), 'Identifies Google Workspace');

  const dnsMicrosoft = await resolveDnsDetails('microsoft.com');
  assert(dnsMicrosoft.hasMxRecords && dnsMicrosoft.mailProvider.includes('Microsoft'), 'Identifies Microsoft 365');

  // --- Phase 3: Strict End-to-End Validation ---
  console.log('\n--- Testing Strict End-to-End Rejection & Deliverability ---');
  
  // Fake user on real domain -> MUST be INVALID
  const resFakeOnRealDomain = await verifyEmail('fake123456@stripe.com');
  assert(resFakeOnRealDomain.status === 'INVALID', 'Fake username on real domain (fake123456@stripe.com) is rejected as INVALID');
  console.log(`   fake123456@stripe.com status: ${resFakeOnRealDomain.status}, Reason: ${resFakeOnRealDomain.reason}`);

  const resKeyboardSmash = await verifyEmail('asdfghjkl123@microsoft.com');
  assert(resKeyboardSmash.status === 'INVALID', 'Keyboard smash on real domain is rejected as INVALID');

  const resGmail = await verifyEmail('user@gmail.com', { allowFreeDomains: false });
  assert(resGmail.status === 'INVALID', 'Gmail rejected for corporate email');

  const resDisposable = await verifyEmail('temp@yopmail.com');
  assert(resDisposable.status === 'INVALID', 'Disposable email rejected as INVALID');

  const resStripe = await verifyEmail('contact@stripe.com');
  assert(resStripe.isDeliverable && resStripe.isCorporate, 'Real corporate contact@stripe.com is processed');
  console.log(`   contact@stripe.com status: ${resStripe.status}, Provider: ${resStripe.mailProvider}, Score: ${resStripe.score}/100`);

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

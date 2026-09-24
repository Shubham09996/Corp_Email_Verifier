import { validateSyntax } from '../services/syntaxValidator.js';
import { isSuspiciousUsername } from '../services/entropyValidator.js';
import { resolveDnsDetails } from '../services/dnsResolver.js';
import { verifyEmail } from '../services/emailVerificationService.js';

async function runAllTests() {
  console.log('====================================================');
  console.log('🧪 Starting 3-Status Verification Engine Tests');
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

  // --- Phase 1: Synthetic & Fake Pattern Detection ---
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

  // --- Phase 3: 3-Status Rejection & Deliverability ---
  console.log('\n--- Testing 3-Status Pipeline (VALID / INVALID / CATCH_ALL) ---');
  
  // Fake user on real domain -> INVALID
  const resFakeOnRealDomain = await verifyEmail('fake123456@stripe.com');
  assert(resFakeOnRealDomain.status === 'INVALID', 'Fake username on real domain (fake123456@stripe.com) is INVALID');
  console.log(`   fake123456@stripe.com status: ${resFakeOnRealDomain.status}`);

  // Fake keyboard smash -> INVALID
  const resKeyboardSmash = await verifyEmail('asdfghjkl123@microsoft.com');
  assert(resKeyboardSmash.status === 'INVALID', 'Keyboard smash is INVALID');

  // Gmail -> INVALID
  const resGmail = await verifyEmail('user@gmail.com', { allowFreeDomains: false });
  assert(resGmail.status === 'INVALID', 'Gmail is INVALID for corporate email');

  // Disposable -> INVALID
  const resDisposable = await verifyEmail('temp@yopmail.com');
  assert(resDisposable.status === 'INVALID', 'Disposable is INVALID');

  // Real corporate email -> VALID or CATCH_ALL
  const resStripe = await verifyEmail('contact@stripe.com');
  assert(resStripe.status === 'CATCH_ALL' || resStripe.status === 'VALID', 'Stripe corporate email is CATCH_ALL or VALID');
  console.log(`   contact@stripe.com status: ${resStripe.status}, Score: ${resStripe.score}/100`);

  const resMicrosoft = await verifyEmail('employee@microsoft.com');
  assert(resMicrosoft.status === 'VALID' || resMicrosoft.status === 'CATCH_ALL', 'Microsoft employee email is VALID or CATCH_ALL');
  console.log(`   employee@microsoft.com status: ${resMicrosoft.status}, Score: ${resMicrosoft.score}/100`);

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

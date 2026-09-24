import axios from 'axios';

const BASE = 'http://localhost:3000';

async function testAll() {
  console.log('Testing Batch Verification Endpoint (POST /api/verify/batch)...');
  const batchResp = await axios.post(`${BASE}/api/verify/batch`, {
    emails: [
      'careers@openai.com',
      'hr@microsoft.com',
      'user123@yahoo.com',
      'temp@10minutemail.com',
      'nonexistent123987@google.com'
    ]
  });

  console.log('Batch Result Summary:', {
    total: batchResp.data.data.total,
    valid: batchResp.data.data.validCount,
    protected: batchResp.data.data.protectedCount,
    catchAll: batchResp.data.data.catchAllCount,
    invalid: batchResp.data.data.invalidCount
  });

  console.log('\nTesting Domain Age Endpoint (POST /api/domain-age)...');
  const ageResp = await axios.post(`${BASE}/api/domain-age`, {
    domain: 'stripe.com'
  });
  console.log('Domain Age Result for stripe.com:', JSON.stringify(ageResp.data, null, 2));
}

testAll().catch(console.error);

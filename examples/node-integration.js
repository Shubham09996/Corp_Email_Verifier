import axios from 'axios';

const EMAIL_API_URL = process.env.EMAIL_VERIFICATION_API_URL || 'http://localhost:3000';
const PROJECT_ID = process.env.PROJECT_ID || 'project_1';
const API_KEY = process.env.API_KEY || 'secret_key_1';

async function verifyEmail(email, referenceId = null) {
  try {
    const response = await axios.post(`${EMAIL_API_URL}/api/verify`, {
      email,
      referenceId,
      options: {
        allowFreeDomains: false,
        checkSmtp: true,
        checkDomainAge: true
      }
    }, {
      headers: {
        'X-Project-Id': PROJECT_ID,
        'X-API-Key': API_KEY
      }
    });

    const result = response.data.data;
    console.log('\n--- Verification Result ---');
    console.log(`Email: ${result.email}`);
    console.log(`Status: ${result.status}`); // 'VALID' | 'CATCH_ALL' | 'PROTECTED' | 'INVALID'
    console.log(`Score: ${result.score}/100`);
    console.log(`Deliverable: ${result.isDeliverable}`);
    console.log(`Corporate: ${result.isCorporate}`);
    console.log(`Domain Age: ${result.details.domainAge?.ageYears || 'N/A'} years`);
    return result;
  } catch (error) {
    console.error('Email Verification Failed:', error.response?.data || error.message);
    throw error;
  }
}

async function runDemo() {
  console.log('Testing Email Verification API Project-Wise...');
  await verifyEmail('support@stripe.com', 'REF_001');
  await verifyEmail('john.doe@gmail.com', 'REF_002');
}

runDemo().catch(console.error);

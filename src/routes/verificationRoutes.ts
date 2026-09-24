import { Router } from 'express';
import {
  handleVerifySingleEmail,
  handleVerifyBatchEmails,
  handleDomainAge,
  handleHealthCheck
} from '../controllers/verificationController.js';
import { projectAuth } from '../middleware/apiKeyAuth.js';

const router = Router();

// Public Health Check
router.get('/health', handleHealthCheck);
router.get('/api/health', handleHealthCheck);

// Protected API Routes
router.use(projectAuth);

// Single Email Verification
router.post('/api/verify', handleVerifySingleEmail);
router.get('/api/verify', handleVerifySingleEmail);

// Batch Email Verification
router.post('/api/verify/batch', handleVerifyBatchEmails);

// Domain Age & Corporate Legitimacy
router.post('/api/domain-age', handleDomainAge);
router.get('/api/domain-age/:domain', handleDomainAge);

export default router;

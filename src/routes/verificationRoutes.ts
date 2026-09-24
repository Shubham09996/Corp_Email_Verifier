import { Router } from 'express';
import {
  handleVerifySingleEmail,
  handleVerifyBatchEmails,
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

export default router;

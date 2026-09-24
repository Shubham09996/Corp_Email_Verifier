import axios, { AxiosInstance } from 'axios';
import { VerificationResult, BatchVerificationResult, EmailVerificationOptions } from '../types/index.js';

export interface EmailVerifierClientConfig {
  baseUrl: string;
  projectId?: string;
  apiKey?: string;
  timeoutMs?: number;
}

/**
 * Lightweight Client SDK for integrating Email Verification API into any project.
 * 
 * Usage:
 * ```typescript
 * const verifier = new EmailVerifierClient({
 *   baseUrl: 'https://your-api.onrender.com',
 *   projectId: 'project_1',
 *   apiKey: 'secret_key_1'
 * });
 * 
 * const res = await verifier.verifyEmail('employee@company.com');
 * ```
 */
export class EmailVerifierClient {
  private client: AxiosInstance;
  private projectId?: string;

  constructor(config: EmailVerifierClientConfig) {
    this.projectId = config.projectId;
    this.client = axios.create({
      baseURL: config.baseUrl.replace(/\/$/, ''),
      timeout: config.timeoutMs || 15000,
      headers: {
        'Content-Type': 'application/json',
        ...(config.projectId ? { 'X-Project-Id': config.projectId } : {}),
        ...(config.apiKey ? { 'X-API-Key': config.apiKey } : {})
      }
    });
  }

  /**
   * Verify single email address.
   */
  async verifyEmail(
    email: string,
    referenceId?: string,
    options?: EmailVerificationOptions
  ): Promise<{ success: boolean; projectId?: string; referenceId?: string; data: VerificationResult }> {
    const response = await this.client.post('/api/verify', {
      email,
      projectId: this.projectId,
      referenceId,
      options
    });
    return response.data;
  }

  /**
   * Batch verify list of emails.
   */
  async verifyBatch(
    emails: string[],
    options?: EmailVerificationOptions,
    concurrency = 5
  ): Promise<{ success: boolean; projectId?: string; data: BatchVerificationResult }> {
    const response = await this.client.post('/api/verify/batch', {
      emails,
      projectId: this.projectId,
      options,
      concurrency
    });
    return response.data;
  }

  /**
   * Check domain creation date and age.
   */
  async getDomainAge(domain: string): Promise<{
    success: boolean;
    projectId?: string;
    data: {
      domain: string;
      creationDate: string | null;
      ageYears: number | null;
      ageDays: number | null;
      isNewDomain: boolean;
      registrar: string | null;
      status?: string[];
      source: string;
    };
  }> {
    const response = await this.client.post('/api/domain-age', {
      domain,
      projectId: this.projectId
    });
    return response.data;
  }

  /**
   * Check API health status.
   */
  async checkHealth(): Promise<{ status: string; uptimeSeconds: number; timestamp: string }> {
    const response = await this.client.get('/api/health');
    return response.data;
  }
}

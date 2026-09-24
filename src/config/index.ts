import dotenv from 'dotenv';
dotenv.config();

function parseProjectKeys(raw: string): Map<string, string> {
  const map = new Map<string, string>();
  if (!raw || !raw.trim()) return map;

  if (raw.trim().startsWith('{')) {
    try {
      const obj = JSON.parse(raw);
      for (const [k, v] of Object.entries(obj)) {
        if (typeof v === 'string') map.set(k.trim(), v.trim());
      }
      return map;
    } catch {
      // fallback
    }
  }

  const pairs = raw.split(',');
  for (const pair of pairs) {
    const parts = pair.split(':');
    if (parts.length === 2) {
      map.set(parts[0].trim(), parts[1].trim());
    } else if (parts.length === 1 && parts[0].trim()) {
      map.set(parts[0].trim(), parts[0].trim());
    }
  }
  return map;
}

export const config = {
  port: parseInt(process.env.PORT || '3000', 10),
  host: process.env.HOST || '0.0.0.0',
  nodeEnv: process.env.NODE_ENV || 'development',
  
  // Security / Project-Based Authentication
  masterApiKey: process.env.MASTER_API_KEY || process.env.API_KEY || '',
  projectKeys: parseProjectKeys(process.env.PROJECT_KEYS || process.env.API_CLIENTS || ''),
  
  // SMTP Configuration for Handshake
  smtp: {
    heloDomain: process.env.SMTP_HELO_DOMAIN || 'mail.validator.local',
    mailFrom: process.env.SMTP_MAIL_FROM || 'verify@validator.local',
    timeoutMs: parseInt(process.env.SMTP_TIMEOUT_MS || '7000', 10),
    port: parseInt(process.env.SMTP_PORT || '25', 10)
  },

  // DNS Configuration
  dns: {
    timeoutMs: parseInt(process.env.DNS_TIMEOUT_MS || '3500', 10),
    servers: ['8.8.8.8', '1.1.1.1', '9.9.9.9', '208.67.222.222']
  },

  // Cache Configuration
  cache: {
    domainAgeTtlMs: 24 * 60 * 60 * 1000, // 24 hours
    mxRecordTtlMs: 2 * 60 * 60 * 1000     // 2 hours
  }
};

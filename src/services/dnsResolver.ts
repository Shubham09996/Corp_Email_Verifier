import dns from 'dns';
import axios from 'axios';
import { MxRecord, DnsCheckResult } from '../types/index.js';
import { config } from '../config/index.js';

interface CachedDns {
  data: DnsCheckResult;
  expiresAt: number;
}

const dnsCache = new Map<string, CachedDns>();

const customResolver = new dns.promises.Resolver();
try {
  customResolver.setServers(config.dns.servers);
} catch {
  // Use system default if setting servers fails
}

/**
 * Identify the email provider / security gateway from MX exchange hostnames.
 */
export function identifyMailProvider(mxRecords: MxRecord[]): string {
  if (!mxRecords || mxRecords.length === 0) return 'None';

  const exchanges = mxRecords.map(r => r.exchange.toLowerCase()).join(' ');

  if (exchanges.includes('google.com') || exchanges.includes('googlemail.com') || exchanges.includes('l.google.com')) {
    return 'Google Workspace / Gmail';
  }
  if (exchanges.includes('outlook.com') || exchanges.includes('protection.outlook.com') || exchanges.includes('microsoft.com')) {
    return 'Microsoft 365 / Outlook Enterprise';
  }
  if (exchanges.includes('pphosted.com') || exchanges.includes('proofpoint.com')) {
    return 'Proofpoint Enterprise Protection';
  }
  if (exchanges.includes('mimecast.com')) {
    return 'Mimecast Security Gateway';
  }
  if (exchanges.includes('barracudanetworks.com') || exchanges.includes('barracuda.com')) {
    return 'Barracuda Email Security';
  }
  if (exchanges.includes('iphmx.com') || exchanges.includes('ironport.com') || exchanges.includes('cisco.com')) {
    return 'Cisco IronPort Security';
  }
  if (exchanges.includes('zoho.com') || exchanges.includes('zohomail.com')) {
    return 'Zoho Mail Enterprise';
  }
  if (exchanges.includes('amazonses.com') || exchanges.includes('aws.amazon.com')) {
    return 'Amazon SES / WorkMail';
  }
  if (exchanges.includes('protonmail.ch') || exchanges.includes('proton.me')) {
    return 'Proton Mail Enterprise';
  }
  if (exchanges.includes('cloudflare.net')) {
    return 'Cloudflare Email Routing';
  }
  if (exchanges.includes('sendgrid.net')) {
    return 'SendGrid / Twilio';
  }
  if (exchanges.includes('trendmicro.com') || exchanges.includes('tmes.trendmicro.eu')) {
    return 'Trend Micro Email Security';
  }
  if (exchanges.includes('sophos.com')) {
    return 'Sophos Email Security';
  }

  return 'Custom Corporate Mail Server';
}

/**
 * Resolve MX records with 3-tier fallback (Native, Google DoH, Cloudflare DoH)
 * and perform SPF & DMARC verification.
 */
export async function resolveDnsDetails(domain: string): Promise<DnsCheckResult> {
  const cleanDomain = domain.toLowerCase().trim();

  // Check cache
  const cached = dnsCache.get(cleanDomain);
  if (cached && cached.expiresAt > Date.now()) {
    return cached.data;
  }

  let mxRecords: MxRecord[] = [];
  let resolutionSource: 'NATIVE_DNS' | 'GOOGLE_DOH' | 'CLOUDFLARE_DOH' | 'NONE' = 'NONE';

  // Tier 1: Native DNS
  try {
    const addrs = await customResolver.resolveMx(cleanDomain);
    if (addrs && addrs.length > 0) {
      mxRecords = addrs
        .map(r => ({ exchange: r.exchange.trim().replace(/\.$/, ''), priority: r.priority }))
        .sort((a, b) => a.priority - b.priority);
      resolutionSource = 'NATIVE_DNS';
    }
  } catch {
    // Fallthrough to Tier 2
  }

  // Tier 2: Google DoH
  if (mxRecords.length === 0) {
    try {
      const resp = await axios.get(
        `https://dns.google/resolve?name=${encodeURIComponent(cleanDomain)}&type=MX`,
        { timeout: config.dns.timeoutMs }
      );
      if (resp.data?.Answer && Array.isArray(resp.data.Answer)) {
        for (const item of resp.data.Answer) {
          if (item.type === 15 && item.data) {
            const parts = item.data.trim().split(/\s+/);
            if (parts.length >= 2) {
              const priority = parseInt(parts[0], 10) || 10;
              const exchange = parts[1].replace(/\.$/, '');
              mxRecords.push({ exchange, priority });
            }
          }
        }
        if (mxRecords.length > 0) {
          mxRecords.sort((a, b) => a.priority - b.priority);
          resolutionSource = 'GOOGLE_DOH';
        }
      }
    } catch {
      // Fallthrough to Tier 3
    }
  }

  // Tier 3: Cloudflare DoH
  if (mxRecords.length === 0) {
    try {
      const resp = await axios.get(
        `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(cleanDomain)}&type=MX`,
        {
          headers: { Accept: 'application/dns-json' },
          timeout: config.dns.timeoutMs
        }
      );
      if (resp.data?.Answer && Array.isArray(resp.data.Answer)) {
        for (const item of resp.data.Answer) {
          if (item.type === 15 && item.data) {
            const parts = item.data.trim().split(/\s+/);
            if (parts.length >= 2) {
              const priority = parseInt(parts[0], 10) || 10;
              const exchange = parts[1].replace(/\.$/, '');
              mxRecords.push({ exchange, priority });
            }
          }
        }
        if (mxRecords.length > 0) {
          mxRecords.sort((a, b) => a.priority - b.priority);
          resolutionSource = 'CLOUDFLARE_DOH';
        }
      }
    } catch {
      // All tiers failed
    }
  }

  // Check SPF & DMARC records
  let hasSpf = false;
  let spfRecord: string | null = null;
  let hasDmarc = false;
  let dmarcRecord: string | null = null;

  try {
    const txtRecords = await customResolver.resolveTxt(cleanDomain);
    if (txtRecords && Array.isArray(txtRecords)) {
      for (const record of txtRecords) {
        const joined = Array.isArray(record) ? record.join('') : record;
        if (joined.toLowerCase().startsWith('v=spf1')) {
          hasSpf = true;
          spfRecord = joined;
          break;
        }
      }
    }
  } catch {
    // SPF query ignored
  }

  try {
    const dmarcTxt = await customResolver.resolveTxt(`_dmarc.${cleanDomain}`);
    if (dmarcTxt && Array.isArray(dmarcTxt)) {
      for (const record of dmarcTxt) {
        const joined = Array.isArray(record) ? record.join('') : record;
        if (joined.toLowerCase().startsWith('v=dmarc1')) {
          hasDmarc = true;
          dmarcRecord = joined;
          break;
        }
      }
    }
  } catch {
    // DMARC query ignored
  }

  const result: DnsCheckResult = {
    hasMxRecords: mxRecords.length > 0,
    mxRecords,
    primaryMx: mxRecords[0]?.exchange || null,
    mailProvider: identifyMailProvider(mxRecords),
    hasSpf,
    hasDmarc,
    spfRecord,
    dmarcRecord,
    resolutionSource,
    ...(mxRecords.length === 0 && {
      error: `No valid mail exchange (MX) records found for domain '${cleanDomain}'.`
    })
  };

  // Cache DNS result
  dnsCache.set(cleanDomain, {
    data: result,
    expiresAt: Date.now() + config.cache.mxRecordTtlMs
  });

  return result;
}

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
  // fallback to system default
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

async function resolveMxWithDoHFallback(cleanDomain: string): Promise<{ mxRecords: MxRecord[]; source: 'NATIVE_DNS' | 'GOOGLE_DOH' | 'CLOUDFLARE_DOH' | 'NONE' }> {
  // 1. Native DNS
  try {
    const addrs = await customResolver.resolveMx(cleanDomain);
    if (addrs && addrs.length > 0) {
      const sorted = addrs
        .map(r => ({ exchange: r.exchange.trim().replace(/\.$/, ''), priority: r.priority }))
        .sort((a, b) => a.priority - b.priority);
      return { mxRecords: sorted, source: 'NATIVE_DNS' };
    }
  } catch {
    // fallback
  }

  // 2. Google DoH
  try {
    const resp = await axios.get(
      `https://dns.google/resolve?name=${encodeURIComponent(cleanDomain)}&type=MX`,
      { timeout: config.dns.timeoutMs }
    );
    if (resp.data?.Answer && Array.isArray(resp.data.Answer)) {
      const mxList: MxRecord[] = [];
      for (const item of resp.data.Answer) {
        if (item.type === 15 && item.data) {
          const parts = item.data.trim().split(/\s+/);
          if (parts.length >= 2) {
            mxList.push({ priority: parseInt(parts[0], 10) || 10, exchange: parts[1].replace(/\.$/, '') });
          }
        }
      }
      if (mxList.length > 0) {
        mxList.sort((a, b) => a.priority - b.priority);
        return { mxRecords: mxList, source: 'GOOGLE_DOH' };
      }
    }
  } catch {
    // fallback
  }

  // 3. Cloudflare DoH
  try {
    const resp = await axios.get(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(cleanDomain)}&type=MX`,
      { headers: { Accept: 'application/dns-json' }, timeout: config.dns.timeoutMs }
    );
    if (resp.data?.Answer && Array.isArray(resp.data.Answer)) {
      const mxList: MxRecord[] = [];
      for (const item of resp.data.Answer) {
        if (item.type === 15 && item.data) {
          const parts = item.data.trim().split(/\s+/);
          if (parts.length >= 2) {
            mxList.push({ priority: parseInt(parts[0], 10) || 10, exchange: parts[1].replace(/\.$/, '') });
          }
        }
      }
      if (mxList.length > 0) {
        mxList.sort((a, b) => a.priority - b.priority);
        return { mxRecords: mxList, source: 'CLOUDFLARE_DOH' };
      }
    }
  } catch {
    // fail
  }

  return { mxRecords: [], source: 'NONE' };
}

async function resolveSpf(cleanDomain: string): Promise<{ hasSpf: boolean; spfRecord: string | null }> {
  try {
    const txtRecords = await customResolver.resolveTxt(cleanDomain);
    if (txtRecords && Array.isArray(txtRecords)) {
      for (const record of txtRecords) {
        const joined = Array.isArray(record) ? record.join('') : record;
        if (joined.toLowerCase().startsWith('v=spf1')) {
          return { hasSpf: true, spfRecord: joined };
        }
      }
    }
  } catch {
    // ignore
  }
  return { hasSpf: false, spfRecord: null };
}

async function resolveDmarc(cleanDomain: string): Promise<{ hasDmarc: boolean; dmarcRecord: string | null }> {
  try {
    const dmarcTxt = await customResolver.resolveTxt(`_dmarc.${cleanDomain}`);
    if (dmarcTxt && Array.isArray(dmarcTxt)) {
      for (const record of dmarcTxt) {
        const joined = Array.isArray(record) ? record.join('') : record;
        if (joined.toLowerCase().startsWith('v=dmarc1')) {
          return { hasDmarc: true, dmarcRecord: joined };
        }
      }
    }
  } catch {
    // ignore
  }
  return { hasDmarc: false, dmarcRecord: null };
}

/**
 * Parallel DNS resolution for maximum speed.
 */
export async function resolveDnsDetails(domain: string): Promise<DnsCheckResult> {
  const cleanDomain = domain.toLowerCase().trim();

  // 1. Cache hit -> Instant (< 1ms)
  const cached = dnsCache.get(cleanDomain);
  if (cached && cached.expiresAt > Date.now()) {
    return cached.data;
  }

  // 2. Parallel Resolution (MX + SPF + DMARC at the exact same time)
  const [mxResult, spfResult, dmarcResult] = await Promise.all([
    resolveMxWithDoHFallback(cleanDomain),
    resolveSpf(cleanDomain),
    resolveDmarc(cleanDomain)
  ]);

  const result: DnsCheckResult = {
    hasMxRecords: mxResult.mxRecords.length > 0,
    mxRecords: mxResult.mxRecords,
    primaryMx: mxResult.mxRecords[0]?.exchange || null,
    mailProvider: identifyMailProvider(mxResult.mxRecords),
    hasSpf: spfResult.hasSpf,
    hasDmarc: dmarcResult.hasDmarc,
    spfRecord: spfResult.spfRecord,
    dmarcRecord: dmarcResult.dmarcRecord,
    resolutionSource: mxResult.source,
    ...(mxResult.mxRecords.length === 0 && {
      error: `No valid mail exchange (MX) records found for domain '${cleanDomain}'.`
    })
  };

  // Cache result for 2 hours
  dnsCache.set(cleanDomain, {
    data: result,
    expiresAt: Date.now() + config.cache.mxRecordTtlMs
  });

  return result;
}

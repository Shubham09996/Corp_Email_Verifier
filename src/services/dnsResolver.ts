import dns from 'dns';
import axios from 'axios';
import { MxRecord, DnsCheckResult } from '../types/index.js';
import { config } from '../config/index.js';

interface CachedMx {
  records: MxRecord[];
  source: 'NATIVE_DNS' | 'GOOGLE_DOH' | 'CLOUDFLARE_DOH';
  expiresAt: number;
}

const mxCache = new Map<string, CachedMx>();

// Configure a custom DNS resolver with reliable nameservers
const customResolver = new dns.promises.Resolver();
try {
  customResolver.setServers(config.dns.servers);
} catch (e) {
  console.warn('Could not set custom DNS servers, using system default.', e);
}

/**
 * Resolve MX records using 3-Tier fallback:
 * 1. Native Node.js DNS (with 8.8.8.8, 1.1.1.1, 9.9.9.9)
 * 2. Google Public DNS DoH (JSON)
 * 3. Cloudflare DNS DoH (JSON)
 */
export async function resolveMxRecords(domain: string): Promise<DnsCheckResult> {
  const cleanDomain = domain.toLowerCase().trim();

  // Check in-memory cache
  const cached = mxCache.get(cleanDomain);
  if (cached && cached.expiresAt > Date.now()) {
    return {
      hasMxRecords: cached.records.length > 0,
      mxRecords: cached.records,
      primaryMx: cached.records[0]?.exchange || null,
      resolutionSource: cached.source
    };
  }

  // Tier 1: Native Node.js DNS
  try {
    const addrs = await customResolver.resolveMx(cleanDomain);
    if (addrs && addrs.length > 0) {
      const sorted: MxRecord[] = addrs
        .map(r => ({ exchange: r.exchange.trim().replace(/\.$/, ''), priority: r.priority }))
        .sort((a, b) => a.priority - b.priority);

      mxCache.set(cleanDomain, {
        records: sorted,
        source: 'NATIVE_DNS',
        expiresAt: Date.now() + config.cache.mxRecordTtlMs
      });

      return {
        hasMxRecords: true,
        mxRecords: sorted,
        primaryMx: sorted[0].exchange,
        resolutionSource: 'NATIVE_DNS'
      };
    }
  } catch {
    // Fallthrough to Tier 2
  }

  // Tier 2: Google Public DNS DoH
  try {
    const resp = await axios.get(
      `https://dns.google/resolve?name=${encodeURIComponent(cleanDomain)}&type=MX`,
      { timeout: config.dns.timeoutMs }
    );

    if (resp.data?.Answer && Array.isArray(resp.data.Answer)) {
      const parsed: MxRecord[] = [];
      for (const item of resp.data.Answer) {
        if (item.type === 15 && item.data) {
          const parts = item.data.trim().split(/\s+/);
          if (parts.length >= 2) {
            const priority = parseInt(parts[0], 10) || 10;
            const exchange = parts[1].replace(/\.$/, '');
            parsed.push({ exchange, priority });
          }
        }
      }

      if (parsed.length > 0) {
        const sorted = parsed.sort((a, b) => a.priority - b.priority);
        mxCache.set(cleanDomain, {
          records: sorted,
          source: 'GOOGLE_DOH',
          expiresAt: Date.now() + config.cache.mxRecordTtlMs
        });

        return {
          hasMxRecords: true,
          mxRecords: sorted,
          primaryMx: sorted[0].exchange,
          resolutionSource: 'GOOGLE_DOH'
        };
      }
    }
  } catch {
    // Fallthrough to Tier 3
  }

  // Tier 3: Cloudflare DNS DoH
  try {
    const resp = await axios.get(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(cleanDomain)}&type=MX`,
      {
        headers: { Accept: 'application/dns-json' },
        timeout: config.dns.timeoutMs
      }
    );

    if (resp.data?.Answer && Array.isArray(resp.data.Answer)) {
      const parsed: MxRecord[] = [];
      for (const item of resp.data.Answer) {
        if (item.type === 15 && item.data) {
          const parts = item.data.trim().split(/\s+/);
          if (parts.length >= 2) {
            const priority = parseInt(parts[0], 10) || 10;
            const exchange = parts[1].replace(/\.$/, '');
            parsed.push({ exchange, priority });
          }
        }
      }

      if (parsed.length > 0) {
        const sorted = parsed.sort((a, b) => a.priority - b.priority);
        mxCache.set(cleanDomain, {
          records: sorted,
          source: 'CLOUDFLARE_DOH',
          expiresAt: Date.now() + config.cache.mxRecordTtlMs
        });

        return {
          hasMxRecords: true,
          mxRecords: sorted,
          primaryMx: sorted[0].exchange,
          resolutionSource: 'CLOUDFLARE_DOH'
        };
      }
    }
  } catch {
    // Resolution failed on all tiers
  }

  return {
    hasMxRecords: false,
    mxRecords: [],
    primaryMx: null,
    resolutionSource: 'NONE',
    error: `No valid MX mail server records found for domain '${cleanDomain}'.`
  };
}

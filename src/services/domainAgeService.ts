import axios from 'axios';
import whoisJson from 'whois-json';
import { DomainAgeResult } from '../types/index.js';
import { config } from '../config/index.js';

interface CachedDomainAge {
  data: DomainAgeResult;
  expiresAt: number;
}

const domainAgeCache = new Map<string, CachedDomainAge>();

/**
 * Calculate domain age (years, days, creation date, registrar) via RDAP and WHOIS fallback.
 */
export async function getDomainAge(domain: string): Promise<DomainAgeResult> {
  const cleanDomain = domain.toLowerCase().trim();

  // Check cache first
  const cached = domainAgeCache.get(cleanDomain);
  if (cached && cached.expiresAt > Date.now()) {
    return {
      ...cached.data,
      source: 'CACHE'
    };
  }

  // Tier 1: Query RDAP (Registration Data Access Protocol)
  try {
    const rdapResp = await axios.get(`https://rdap.org/domain/${encodeURIComponent(cleanDomain)}`, {
      timeout: 4500,
      headers: {
        Accept: 'application/rdap+json, application/json'
      }
    });

    if (rdapResp.data) {
      const data = rdapResp.data;
      let regDateStr: string | null = null;

      // Extract registration date from events
      if (Array.isArray(data.events)) {
        for (const evt of data.events) {
          if (
            evt.eventAction === 'registration' ||
            evt.eventAction === 'created' ||
            evt.eventAction === 'transfer'
          ) {
            regDateStr = evt.eventDate;
            if (evt.eventAction === 'registration') break;
          }
        }
      }

      // Extract registrar
      let registrar: string | null = null;
      if (Array.isArray(data.entities)) {
        for (const ent of data.entities) {
          if (Array.isArray(ent.roles) && ent.roles.includes('registrar')) {
            registrar = ent.vcardArray?.[1]?.find((item: any) => item[0] === 'fn')?.[3] || ent.handle || null;
            break;
          }
        }
      }

      if (regDateStr) {
        const result = buildDomainAgeResult(cleanDomain, regDateStr, registrar, data.status, 'RDAP');
        domainAgeCache.set(cleanDomain, {
          data: result,
          expiresAt: Date.now() + config.cache.domainAgeTtlMs
        });
        return result;
      }
    }
  } catch {
    // Fallback to WHOIS
  }

  // Tier 2: Query WHOIS via whois-json
  try {
    const whoisData: any = await whoisJson(cleanDomain, { timeout: 4500 });
    if (whoisData) {
      const creationDateStr =
        whoisData.creationDate ||
        whoisData.created ||
        whoisData.creationDateUtc ||
        whoisData.registered ||
        whoisData.createdDate ||
        whoisData.domainCreateDate;

      const registrar =
        whoisData.registrar ||
        whoisData.registrarName ||
        whoisData.sponsoringRegistrar ||
        null;

      if (creationDateStr) {
        const result = buildDomainAgeResult(
          cleanDomain,
          creationDateStr,
          registrar,
          whoisData.status ? [whoisData.status] : undefined,
          'WHOIS'
        );

        domainAgeCache.set(cleanDomain, {
          data: result,
          expiresAt: Date.now() + config.cache.domainAgeTtlMs
        });
        return result;
      }
    }
  } catch {
    // Both failed
  }

  // If unavailable
  const unavailableResult: DomainAgeResult = {
    domain: cleanDomain,
    creationDate: null,
    ageDays: null,
    ageYears: null,
    registrar: null,
    isNewDomain: false,
    source: 'UNAVAILABLE'
  };

  return unavailableResult;
}

function buildDomainAgeResult(
  domain: string,
  rawCreationDate: string,
  registrar: string | null,
  domainStatus?: string[] | string,
  source: 'RDAP' | 'WHOIS' = 'RDAP'
): DomainAgeResult {
  const creationDate = new Date(rawCreationDate);
  const isValidDate = !isNaN(creationDate.getTime());

  if (!isValidDate) {
    return {
      domain,
      creationDate: null,
      ageDays: null,
      ageYears: null,
      registrar,
      isNewDomain: false,
      source
    };
  }

  const now = new Date();
  const diffTime = Math.abs(now.getTime() - creationDate.getTime());
  const ageDays = Math.floor(diffTime / (1000 * 60 * 60 * 24));
  const ageYears = parseFloat((ageDays / 365.25).toFixed(2));
  const isNewDomain = ageDays < 90; // Newly registered within 90 days

  const statuses = Array.isArray(domainStatus)
    ? domainStatus
    : domainStatus
    ? [domainStatus]
    : undefined;

  return {
    domain,
    creationDate: creationDate.toISOString().split('T')[0],
    ageDays,
    ageYears,
    registrar: registrar || null,
    isNewDomain,
    domainStatus: statuses,
    source
  };
}

import https from "https";

interface NvdCveItem {
  id: string;
  sourceIdentifier?: string;
  published: string;
  lastModified: string;
  vulnStatus?: string;
  descriptions: { lang: string; value: string }[];
  metrics?: {
    cvssMetricV31?: {
      source: string;
      type: string;
      cvssData: {
        version: string;
        vectorString: string;
        attackVector: string;
        attackComplexity: string;
        privilegesRequired: string;
        userInteraction: string;
        scope: string;
        confidentialityImpact: string;
        integrityImpact: string;
        availabilityImpact: string;
        baseScore: number;
        baseSeverity: string;
      };
      exploitabilityScore: number;
      impactScore: number;
    }[];
    cvssMetricV2?: {
      source: string;
      cvssData: {
        baseScore: number;
      };
    }[];
  };
  weaknesses?: {
    source: string;
    type: string;
    description: { lang: string; value: string }[];
  }[];
  configurations?: {
    nodes: {
      operator: string;
      negate: boolean;
      cpeMatch: {
        vulnerable: boolean;
        criteria: string;
        matchCriteriaId: string;
        versionStartIncluding?: string;
        versionEndExcluding?: string;
        versionEndIncluding?: string;
      }[];
    }[];
  }[];
  references: {
    url: string;
    source?: string;
    tags?: string[];
  }[];
}

export interface CveResult {
  id: string;
  description: string;
  published: string;
  lastModified: string;
  severity: string;
  cvssScore: number | null;
  cvssVector: string | null;
  attackVector: string | null;
  attackComplexity: string | null;
  privilegesRequired: string | null;
  userInteraction: string | null;
  scope: string | null;
  confidentialityImpact: string | null;
  integrityImpact: string | null;
  availabilityImpact: string | null;
  exploitabilityScore: number | null;
  impactScore: number | null;
  weaknesses: string[];
  affectedProducts: string[];
  references: { url: string; tags: string[] }[];
  isKev: boolean;
}

let lastRequestTime = 0;
const MIN_REQUEST_INTERVAL = 6500;

const resultCache = new Map<string, { data: any; timestamp: number }>();
const RESULT_CACHE_TTL = 5 * 60 * 1000;

function getCacheKey(url: string): string {
  return url;
}

function getCachedResult(key: string): any | null {
  const cached = resultCache.get(key);
  if (cached && (Date.now() - cached.timestamp) < RESULT_CACHE_TTL) {
    return cached.data;
  }
  resultCache.delete(key);
  return null;
}

function setCachedResult(key: string, data: any): void {
  if (resultCache.size > 100) {
    const oldestKey = resultCache.keys().next().value;
    if (oldestKey) resultCache.delete(oldestKey);
  }
  resultCache.set(key, { data, timestamp: Date.now() });
}

async function rateLimitedWait(): Promise<void> {
  const now = Date.now();
  const elapsed = now - lastRequestTime;
  const apiKey = process.env.NVD_API_KEY;
  const interval = apiKey ? 1200 : MIN_REQUEST_INTERVAL;

  if (elapsed < interval) {
    await new Promise(resolve => setTimeout(resolve, interval - elapsed));
  }
  lastRequestTime = Date.now();
}

function httpsGet(url: string, retries = 3): Promise<string> {
  return new Promise((resolve, reject) => {
    const headers: Record<string, string> = { "User-Agent": "AegisAI360-CVE-Scanner/1.0" };
    const apiKey = process.env.NVD_API_KEY;
    if (apiKey) {
      headers["apiKey"] = apiKey;
    }

    const makeRequest = (attempt: number) => {
      const req = https.get(url, { headers }, (res) => {
        let data = "";
        res.on("data", (chunk) => (data += chunk));
        res.on("end", () => {
          if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
            resolve(data);
          } else if ((res.statusCode === 403 || res.statusCode === 429) && attempt < retries) {
            const waitTime = Math.pow(2, attempt) * 6000;
            console.log(`NVD API rate limited (${res.statusCode}), retrying in ${waitTime / 1000}s (attempt ${attempt + 1}/${retries})`);
            setTimeout(() => makeRequest(attempt + 1), waitTime);
          } else {
            reject(new Error(`NVD API returned HTTP ${res.statusCode}. ${res.statusCode === 403 ? "Rate limited - try again in a few seconds, or configure NVD_API_KEY for higher rate limits (free at https://nvd.nist.gov/developers/request-an-api-key)." : data.slice(0, 200)}`));
          }
        });
      });
      req.on("error", (err) => {
        if (attempt < retries) {
          setTimeout(() => makeRequest(attempt + 1), 3000);
        } else {
          reject(err);
        }
      });
      req.setTimeout(20000, () => {
        req.destroy();
        if (attempt < retries) {
          setTimeout(() => makeRequest(attempt + 1), 3000);
        } else {
          reject(new Error("NVD API request timeout after multiple retries"));
        }
      });
    };

    makeRequest(0);
  });
}

function parseCveItem(item: NvdCveItem): CveResult {
  const desc = item.descriptions.find((d) => d.lang === "en")?.value || item.descriptions[0]?.value || "";

  let severity = "UNKNOWN";
  let cvssScore: number | null = null;
  let cvssVector: string | null = null;
  let attackVector: string | null = null;
  let attackComplexity: string | null = null;
  let privilegesRequired: string | null = null;
  let userInteraction: string | null = null;
  let scope: string | null = null;
  let confidentialityImpact: string | null = null;
  let integrityImpact: string | null = null;
  let availabilityImpact: string | null = null;
  let exploitabilityScore: number | null = null;
  let impactScore: number | null = null;

  const v31 = item.metrics?.cvssMetricV31?.[0];
  if (v31) {
    cvssScore = v31.cvssData.baseScore;
    severity = v31.cvssData.baseSeverity;
    cvssVector = v31.cvssData.vectorString;
    attackVector = v31.cvssData.attackVector;
    attackComplexity = v31.cvssData.attackComplexity;
    privilegesRequired = v31.cvssData.privilegesRequired;
    userInteraction = v31.cvssData.userInteraction;
    scope = v31.cvssData.scope;
    confidentialityImpact = v31.cvssData.confidentialityImpact;
    integrityImpact = v31.cvssData.integrityImpact;
    availabilityImpact = v31.cvssData.availabilityImpact;
    exploitabilityScore = v31.exploitabilityScore;
    impactScore = v31.impactScore;
  } else if (item.metrics?.cvssMetricV2?.[0]) {
    cvssScore = item.metrics.cvssMetricV2[0].cvssData.baseScore;
    if (cvssScore >= 9.0) severity = "CRITICAL";
    else if (cvssScore >= 7.0) severity = "HIGH";
    else if (cvssScore >= 4.0) severity = "MEDIUM";
    else severity = "LOW";
  }

  const weaknesses: string[] = [];
  if (item.weaknesses) {
    for (const w of item.weaknesses) {
      for (const d of w.description) {
        if (d.lang === "en" && d.value !== "NVD-CWE-noinfo" && d.value !== "NVD-CWE-Other") {
          weaknesses.push(d.value);
        }
      }
    }
  }

  const affectedProducts: string[] = [];
  if (item.configurations) {
    for (const config of item.configurations) {
      for (const node of config.nodes) {
        for (const match of node.cpeMatch) {
          if (match.vulnerable) {
            const parts = match.criteria.split(":");
            if (parts.length >= 5) {
              const vendor = parts[3];
              const product = parts[4];
              const version = parts[5] !== "*" ? parts[5] : "";
              const label = version ? `${vendor}/${product} ${version}` : `${vendor}/${product}`;
              if (!affectedProducts.includes(label)) {
                affectedProducts.push(label);
              }
            }
          }
        }
      }
    }
  }

  const references = item.references.map((r) => ({
    url: r.url,
    tags: r.tags || [],
  }));

  const isKev = references.some(
    (r) => r.tags.includes("Exploit") || r.url.includes("cisa.gov")
  );

  return {
    id: item.id,
    description: desc,
    published: item.published,
    lastModified: item.lastModified,
    severity,
    cvssScore,
    cvssVector,
    attackVector,
    attackComplexity,
    privilegesRequired,
    userInteraction,
    scope,
    confidentialityImpact,
    integrityImpact,
    availabilityImpact,
    exploitabilityScore,
    impactScore,
    weaknesses,
    affectedProducts: affectedProducts.slice(0, 20),
    references: references.slice(0, 15),
    isKev,
  };
}

export async function searchCves(params: {
  keyword?: string;
  cveId?: string;
  severity?: string;
  resultsPerPage?: number;
  startIndex?: number;
}): Promise<{ results: CveResult[]; totalResults: number }> {
  const queryParts: string[] = [];

  if (params.cveId) {
    queryParts.push(`cveId=${encodeURIComponent(params.cveId)}`);
  } else if (params.keyword) {
    queryParts.push(`keywordSearch=${encodeURIComponent(params.keyword)}`);
  }

  if (params.severity && !params.cveId) {
    queryParts.push(`cvssV3Severity=${encodeURIComponent(params.severity.toUpperCase())}`);
  }

  const perPage = Math.min(params.resultsPerPage || 20, 50);
  queryParts.push(`resultsPerPage=${perPage}`);
  if (params.startIndex) {
    queryParts.push(`startIndex=${params.startIndex}`);
  }

  const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?${queryParts.join("&")}`;

  const cached = getCachedResult(getCacheKey(url));
  if (cached) return cached;

  await rateLimitedWait();

  const raw = await httpsGet(url);
  const data = JSON.parse(raw);
  const vulnerabilities = data.vulnerabilities || [];
  const results = vulnerabilities.map((v: any) => parseCveItem(v.cve));
  const result = { results, totalResults: data.totalResults || 0 };

  setCachedResult(getCacheKey(url), result);
  return result;
}

export async function getCveDetail(cveId: string): Promise<CveResult | null> {
  const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(cveId)}`;

  const cached = getCachedResult(getCacheKey(url));
  if (cached) return cached;

  await rateLimitedWait();

  const raw = await httpsGet(url);
  const data = JSON.parse(raw);
  const vulnerabilities = data.vulnerabilities || [];
  if (vulnerabilities.length === 0) return null;

  const result = parseCveItem(vulnerabilities[0].cve);
  setCachedResult(getCacheKey(url), result);
  return result;
}

export async function getRecentCves(severity?: string): Promise<{ results: CveResult[]; totalResults: number }> {
  const now = new Date();
  const weekAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
  const pubStartDate = weekAgo.toISOString().replace(/\.\d{3}Z$/, ".000");
  const pubEndDate = now.toISOString().replace(/\.\d{3}Z$/, ".000");

  const queryParts = [
    `pubStartDate=${pubStartDate}`,
    `pubEndDate=${pubEndDate}`,
    `resultsPerPage=20`,
  ];

  if (severity) {
    queryParts.push(`cvssV3Severity=${severity.toUpperCase()}`);
  }

  const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?${queryParts.join("&")}`;

  const cached = getCachedResult(getCacheKey(url));
  if (cached) return cached;

  await rateLimitedWait();

  const raw = await httpsGet(url);
  const data = JSON.parse(raw);
  const vulnerabilities = data.vulnerabilities || [];
  const results = vulnerabilities.map((v: any) => parseCveItem(v.cve));
  const result = { results, totalResults: data.totalResults || 0 };

  setCachedResult(getCacheKey(url), result);
  return result;
}

interface BreachResult {
  name: string;
  title: string;
  domain: string;
  breachDate: string;
  addedDate: string;
  modifiedDate: string;
  pwnCount: number;
  description: string;
  dataClasses: string[];
  isVerified: boolean;
  isFabricated: boolean;
  isSensitive: boolean;
  isRetired: boolean;
  isSpamList: boolean;
  logoPath: string | null;
  severity: "critical" | "high" | "medium" | "low";
  riskScore: number;
  recommendations: string[];
}

interface DarkWebCheckResult {
  query: string;
  queryType: "domain" | "email";
  totalBreaches: number;
  totalExposedRecords: number;
  overallRiskScore: number;
  riskLevel: "critical" | "high" | "medium" | "low" | "none";
  breaches: BreachResult[];
  exposedDataTypes: { type: string; count: number }[];
  timeline: { date: string; breachName: string; records: number }[];
  recommendations: string[];
  dataSource: "hibp-api" | "hibp-public" | "hibp-email-api";
  apiKeyConfigured: boolean;
}

let breachCache: { data: any[]; timestamp: number } | null = null;
const CACHE_TTL = 10 * 60 * 1000;

async function fetchAllBreachesFromHIBP(): Promise<any[]> {
  if (breachCache && (Date.now() - breachCache.timestamp) < CACHE_TTL) {
    return breachCache.data;
  }

  const response = await fetch("https://haveibeenpwned.com/api/v3/breaches", {
    headers: {
      "user-agent": "AegisAI360-SOC-Platform",
    },
  });

  if (!response.ok) {
    throw new Error(`HIBP API returned ${response.status}: ${response.statusText}`);
  }

  const data = await response.json();
  breachCache = { data, timestamp: Date.now() };
  return data;
}

function classifyBreachSeverity(breach: any): "critical" | "high" | "medium" | "low" {
  const criticalDataTypes = ["Passwords", "Credit cards", "Bank account numbers", "Social security numbers", "Credit card CVV"];
  const highDataTypes = ["Email addresses", "Phone numbers", "Physical addresses", "Dates of birth", "Government issued IDs"];

  const hasCritical = breach.DataClasses?.some((dc: string) => criticalDataTypes.includes(dc));
  const hasHigh = breach.DataClasses?.some((dc: string) => highDataTypes.includes(dc));

  if (hasCritical && breach.PwnCount > 1000000) return "critical";
  if (hasCritical) return "high";
  if (hasHigh && breach.PwnCount > 500000) return "high";
  if (hasHigh) return "medium";
  return "low";
}

function calculateRiskScore(breach: any): number {
  let score = 0;
  const criticalDataTypes = ["Passwords", "Credit cards", "Bank account numbers", "Social security numbers"];
  const highDataTypes = ["Email addresses", "Phone numbers", "Physical addresses", "Dates of birth"];

  if (breach.DataClasses) {
    for (const dc of breach.DataClasses) {
      if (criticalDataTypes.includes(dc)) score += 25;
      else if (highDataTypes.includes(dc)) score += 15;
      else score += 5;
    }
  }

  if (breach.PwnCount > 10000000) score += 20;
  else if (breach.PwnCount > 1000000) score += 15;
  else if (breach.PwnCount > 100000) score += 10;
  else score += 5;

  if (breach.IsVerified) score += 10;

  const breachAge = (Date.now() - new Date(breach.BreachDate).getTime()) / (365.25 * 24 * 60 * 60 * 1000);
  if (breachAge < 1) score += 15;
  else if (breachAge < 2) score += 10;
  else if (breachAge < 5) score += 5;

  return Math.min(100, score);
}

function generateRecommendations(breach: any): string[] {
  const recs: string[] = [];
  const dataClasses = breach.DataClasses || [];

  if (dataClasses.includes("Passwords")) {
    recs.push("Immediately change passwords for all accounts associated with this service");
    recs.push("Enable multi-factor authentication (MFA) on all accounts");
    recs.push("Check for password reuse across other services and change those passwords too");
  }
  if (dataClasses.includes("Email addresses")) {
    recs.push("Monitor email accounts for phishing attempts related to this breach");
    recs.push("Be cautious of unsolicited emails claiming to be from this service");
  }
  if (dataClasses.includes("Phone numbers")) {
    recs.push("Be alert for SIM swapping attacks and social engineering calls");
    recs.push("Consider using a separate phone number for sensitive accounts");
  }
  if (dataClasses.includes("Credit cards") || dataClasses.includes("Bank account numbers")) {
    recs.push("Contact your bank to issue new cards and monitor for unauthorized transactions");
    recs.push("Place a fraud alert or credit freeze with credit bureaus");
  }
  if (dataClasses.includes("Social security numbers") || dataClasses.includes("Government issued IDs")) {
    recs.push("Place a credit freeze with all major credit bureaus immediately");
    recs.push("Monitor credit reports for unauthorized accounts");
    recs.push("Consider identity theft protection services");
  }
  if (dataClasses.includes("Physical addresses") || dataClasses.includes("Dates of birth")) {
    recs.push("Be vigilant for identity theft attempts using personal information");
  }
  if (recs.length === 0) {
    recs.push("Review your account security settings for this service");
    recs.push("Consider enabling MFA where available");
  }
  return recs;
}

function transformBreachData(breach: any): BreachResult {
  const severity = classifyBreachSeverity(breach);
  const riskScore = calculateRiskScore(breach);
  const recommendations = generateRecommendations(breach);

  return {
    name: breach.Name,
    title: breach.Title,
    domain: breach.Domain || "",
    breachDate: breach.BreachDate,
    addedDate: breach.AddedDate,
    modifiedDate: breach.ModifiedDate,
    pwnCount: breach.PwnCount,
    description: breach.Description,
    dataClasses: breach.DataClasses || [],
    isVerified: breach.IsVerified,
    isFabricated: breach.IsFabricated,
    isSensitive: breach.IsSensitive,
    isRetired: breach.IsRetired,
    isSpamList: breach.IsSpamList,
    logoPath: breach.LogoPath ? `https://haveibeenpwned.com/Content/Images/PwnedLogos/${breach.LogoPath}` : null,
    severity,
    riskScore,
    recommendations,
  };
}

export async function checkDomain(domain: string): Promise<DarkWebCheckResult> {
  const apiKey = process.env.HIBP_API_KEY;
  let rawBreaches: any[] = [];
  let dataSource: DarkWebCheckResult["dataSource"] = "hibp-public";

  if (apiKey) {
    try {
      const response = await fetch(`https://haveibeenpwned.com/api/v3/breaches?domain=${encodeURIComponent(domain)}`, {
        headers: {
          "hibp-api-key": apiKey,
          "user-agent": "AegisAI360-SOC-Platform",
        },
      });
      if (response.ok) {
        rawBreaches = await response.json();
        dataSource = "hibp-api";
      } else if (response.status === 404) {
        rawBreaches = [];
        dataSource = "hibp-api";
      }
    } catch (err) {
      console.error("HIBP domain API lookup failed, falling back to public breach list:", err);
    }
  }

  if (rawBreaches.length === 0 && dataSource !== "hibp-api") {
    try {
      const allBreaches = await fetchAllBreachesFromHIBP();
      const domainLower = domain.toLowerCase();
      rawBreaches = allBreaches.filter((b: any) => {
        const bDomain = (b.Domain || "").toLowerCase();
        const bName = (b.Name || "").toLowerCase();
        const bTitle = (b.Title || "").toLowerCase();
        return bDomain === domainLower ||
               bDomain.endsWith("." + domainLower) ||
               domainLower.endsWith("." + bDomain) ||
               bDomain.includes(domainLower) ||
               bName.includes(domainLower) ||
               bTitle.includes(domainLower);
      });
      dataSource = "hibp-public";
    } catch (err) {
      console.error("HIBP public breach list fetch failed:", err);
      throw new Error("Unable to reach Have I Been Pwned API. Please try again later.");
    }
  }

  const result = buildCheckResult(domain, "domain", rawBreaches);
  return { ...result, dataSource, apiKeyConfigured: !!apiKey };
}

export async function checkEmail(email: string): Promise<DarkWebCheckResult> {
  const apiKey = process.env.HIBP_API_KEY;
  let rawBreaches: any[] = [];
  let dataSource: DarkWebCheckResult["dataSource"] = "hibp-public";

  if (apiKey) {
    try {
      const response = await fetch(`https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(email)}?truncateResponse=false`, {
        headers: {
          "hibp-api-key": apiKey,
          "user-agent": "AegisAI360-SOC-Platform",
        },
      });
      if (response.ok) {
        rawBreaches = await response.json();
        dataSource = "hibp-email-api";
      } else if (response.status === 404) {
        rawBreaches = [];
        dataSource = "hibp-email-api";
      } else if (response.status === 401) {
        throw new Error("Invalid HIBP API key. Please check your HIBP_API_KEY environment variable.");
      }
    } catch (err: any) {
      if (err.message?.includes("Invalid HIBP API key")) throw err;
      console.error("HIBP email lookup failed:", err);
    }
  }

  if (!apiKey) {
    const domain = email.split("@")[1];
    if (domain) {
      try {
        const allBreaches = await fetchAllBreachesFromHIBP();
        const domainLower = domain.toLowerCase();
        rawBreaches = allBreaches.filter((b: any) => {
          const bDomain = (b.Domain || "").toLowerCase();
          return bDomain === domainLower || bDomain.includes(domainLower) || domainLower.includes(bDomain);
        });
        dataSource = "hibp-public";
      } catch (err) {
        console.error("HIBP public breach list fetch failed:", err);
        throw new Error("Unable to reach Have I Been Pwned API. Please try again later.");
      }
    }
  }

  const result = buildCheckResult(email, "email", rawBreaches);
  return {
    ...result,
    dataSource,
    apiKeyConfigured: !!apiKey,
    recommendations: !apiKey
      ? [...result.recommendations, "Configure HIBP_API_KEY for per-email breach lookup (available at haveibeenpwned.com/API/Key for $3.50/month). Without it, results are based on domain-level breach data."]
      : result.recommendations,
  };
}

export async function getAllBreaches(): Promise<any[]> {
  try {
    const allBreaches = await fetchAllBreachesFromHIBP();
    return allBreaches
      .sort((a: any, b: any) => new Date(b.AddedDate || b.BreachDate).getTime() - new Date(a.AddedDate || a.BreachDate).getTime())
      .slice(0, 50)
      .map(transformBreachData);
  } catch (err) {
    console.error("HIBP breaches fetch failed:", err);
    throw new Error("Unable to fetch breach data from Have I Been Pwned. Please try again later.");
  }
}

function buildCheckResult(query: string, queryType: "domain" | "email", rawBreaches: any[]): Omit<DarkWebCheckResult, "dataSource" | "apiKeyConfigured"> {
  const breaches = rawBreaches.map(transformBreachData);
  const totalExposedRecords = breaches.reduce((sum, b) => sum + b.pwnCount, 0);

  const dataTypeMap = new Map<string, number>();
  for (const breach of breaches) {
    for (const dc of breach.dataClasses) {
      dataTypeMap.set(dc, (dataTypeMap.get(dc) || 0) + 1);
    }
  }
  const exposedDataTypes = Array.from(dataTypeMap.entries())
    .map(([type, count]) => ({ type, count }))
    .sort((a, b) => b.count - a.count);

  const timeline = breaches
    .map(b => ({ date: b.breachDate, breachName: b.title, records: b.pwnCount }))
    .sort((a, b) => new Date(a.date).getTime() - new Date(b.date).getTime());

  const overallRiskScore = breaches.length > 0
    ? Math.min(100, Math.round(breaches.reduce((sum, b) => sum + b.riskScore, 0) / breaches.length + breaches.length * 5))
    : 0;

  let riskLevel: "critical" | "high" | "medium" | "low" | "none";
  if (overallRiskScore >= 80) riskLevel = "critical";
  else if (overallRiskScore >= 60) riskLevel = "high";
  else if (overallRiskScore >= 40) riskLevel = "medium";
  else if (overallRiskScore > 0) riskLevel = "low";
  else riskLevel = "none";

  const allRecs = new Set<string>();
  for (const breach of breaches) {
    for (const rec of breach.recommendations) {
      allRecs.add(rec);
    }
  }
  if (breaches.length > 0) {
    allRecs.add("Conduct a comprehensive password audit across all organizational accounts");
    allRecs.add("Implement dark web monitoring as an ongoing security measure");
    allRecs.add("Review and update your incident response plan");
  }

  return {
    query,
    queryType,
    totalBreaches: breaches.length,
    totalExposedRecords,
    overallRiskScore,
    riskLevel,
    breaches,
    exposedDataTypes,
    timeline,
    recommendations: Array.from(allRecs),
  };
}

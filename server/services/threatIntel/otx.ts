export async function otxLookup(indicator: string, type: "ip" | "domain" | "url" | "hash" = "ip"): Promise<any> {
  const apiKey = process.env.OTX_API_KEY;
  if (!apiKey) {
    return {
      source: "AlienVault OTX",
      configured: false,
      indicator,
      type,
      message: "OTX API key not configured. Set OTX_API_KEY environment variable to enable live threat intelligence lookups.",
      setupUrl: "https://otx.alienvault.com/api",
      setupInstructions: "Sign up at otx.alienvault.com, go to Settings > API, and copy your API key (free, unlimited).",
    };
  }

  try {
    const typeMap: Record<string, string> = { ip: "IPv4", domain: "domain", url: "url", hash: "file" };
    const otxType = typeMap[type] || "IPv4";
    const response = await fetch(`https://otx.alienvault.com/api/v1/indicators/${otxType}/${encodeURIComponent(indicator)}/general`, {
      headers: { "X-OTX-API-KEY": apiKey },
    });
    if (!response.ok) {
      const errorText = await response.text();
      return { source: "AlienVault OTX", configured: true, indicator, error: `API returned ${response.status}: ${errorText}` };
    }
    const result = await response.json();
    return { source: "AlienVault OTX", configured: true, indicator, type, data: result };
  } catch (error: any) {
    return { source: "AlienVault OTX", configured: true, indicator, error: error.message };
  }
}

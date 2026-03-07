export async function otxLookup(indicator: string, type: "ip" | "domain" | "url" | "hash" = "ip"): Promise<any> {
  const apiKey = process.env.OTX_API_KEY;
  if (!apiKey) {
    return {
      source: "AlienVault OTX",
      configured: false,
      indicator,
      type,
      message: "OTX API key not configured. Set OTX_API_KEY environment variable to enable live lookups.",
      stub: true,
      data: {
        pulseCount: Math.floor(Math.random() * 20),
        reputation: Math.floor(Math.random() * 5),
        country: "US",
        asn: "AS15169",
        indicator,
        sections: ["general", "geo", "malware", "url_list", "passive_dns"],
        pulses: [
          { name: "Malicious IP Feed", description: "Known malicious IPs", created: new Date().toISOString(), tags: ["malware", "c2"] },
          { name: "Threat Intel Report", description: "Threat intelligence indicators", created: new Date().toISOString(), tags: ["apt", "threat"] },
        ],
      },
    };
  }

  try {
    const typeMap: Record<string, string> = { ip: "IPv4", domain: "domain", url: "url", hash: "file" };
    const otxType = typeMap[type] || "IPv4";
    const response = await fetch(`https://otx.alienvault.com/api/v1/indicators/${otxType}/${encodeURIComponent(indicator)}/general`, {
      headers: { "X-OTX-API-KEY": apiKey },
    });
    const result = await response.json();
    return { source: "AlienVault OTX", configured: true, indicator, type, data: result };
  } catch (error: any) {
    return { source: "AlienVault OTX", configured: true, indicator, error: error.message };
  }
}

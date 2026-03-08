export async function abuseIpdbLookup(ip: string): Promise<any> {
  const apiKey = process.env.ABUSEIPDB_API_KEY;
  if (!apiKey) {
    return {
      source: "AbuseIPDB",
      configured: false,
      ip,
      message: "AbuseIPDB API key not configured. Set ABUSEIPDB_API_KEY environment variable to enable live IP reputation lookups.",
      setupUrl: "https://www.abuseipdb.com/account/api",
      setupInstructions: "Sign up at abuseipdb.com, go to API tab, and create a free API key (1,000 lookups/day).",
    };
  }

  try {
    const response = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`, {
      headers: { Key: apiKey, Accept: "application/json" },
    });
    if (!response.ok) {
      const errorText = await response.text();
      return { source: "AbuseIPDB", configured: true, ip, error: `API returned ${response.status}: ${errorText}` };
    }
    const result = await response.json();
    return { source: "AbuseIPDB", configured: true, ip, data: result.data };
  } catch (error: any) {
    return { source: "AbuseIPDB", configured: true, ip, error: error.message };
  }
}

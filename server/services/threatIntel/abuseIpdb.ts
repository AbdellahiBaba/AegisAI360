export async function abuseIpdbLookup(ip: string): Promise<any> {
  const apiKey = process.env.ABUSEIPDB_API_KEY;
  if (!apiKey) {
    return {
      source: "AbuseIPDB",
      configured: false,
      ip,
      message: "AbuseIPDB API key not configured. Set ABUSEIPDB_API_KEY environment variable to enable live lookups.",
      stub: true,
      data: {
        ipAddress: ip,
        abuseConfidenceScore: Math.floor(Math.random() * 100),
        totalReports: Math.floor(Math.random() * 50),
        countryCode: "US",
        isp: "Example ISP",
        domain: "example.com",
        isWhitelisted: false,
        lastReportedAt: new Date().toISOString(),
        categories: [18, 14, 22],
      },
    };
  }

  try {
    const response = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`, {
      headers: { Key: apiKey, Accept: "application/json" },
    });
    const result = await response.json();
    return { source: "AbuseIPDB", configured: true, ip, data: result.data };
  } catch (error: any) {
    return { source: "AbuseIPDB", configured: true, ip, error: error.message };
  }
}

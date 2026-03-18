export async function safeBrowsingLookup(url: string, overrideKey?: string): Promise<any> {
  const apiKey = overrideKey || process.env.GOOGLE_SAFE_BROWSING_API_KEY;
  if (!apiKey) {
    return {
      source: "Google Safe Browsing",
      configured: false,
      url,
      message: "Google Safe Browsing API key not configured. Set GOOGLE_SAFE_BROWSING_API_KEY to enable live URL threat detection.",
      setupUrl: "https://console.cloud.google.com/apis/library/safebrowsing.googleapis.com",
      setupInstructions: "Enable the Safe Browsing API in Google Cloud Console and create an API key (free tier: 10,000 lookups/day).",
    };
  }

  try {
    const response = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client: { clientId: "aegisai360", clientVersion: "8.2.1" },
        threatInfo: {
          threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
          platformTypes: ["ANY_PLATFORM"],
          threatEntryTypes: ["URL"],
          threatEntries: [{ url }],
        },
      }),
    });
    if (!response.ok) {
      const errorText = await response.text();
      return { source: "Google Safe Browsing", configured: true, url, error: `API returned ${response.status}: ${errorText}` };
    }
    const result = await response.json();
    return {
      source: "Google Safe Browsing",
      configured: true,
      url,
      data: { matches: result.matches || [], safe: !result.matches || result.matches.length === 0 },
    };
  } catch (error: any) {
    return { source: "Google Safe Browsing", configured: true, url, error: error.message };
  }
}

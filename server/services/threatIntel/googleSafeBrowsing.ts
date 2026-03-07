export async function safeBrowsingLookup(url: string): Promise<any> {
  const apiKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY;
  if (!apiKey) {
    return {
      source: "Google Safe Browsing",
      configured: false,
      url,
      message: "Google Safe Browsing API key not configured. Set GOOGLE_SAFE_BROWSING_API_KEY to enable live lookups.",
      stub: true,
      data: {
        matches: Math.random() > 0.6 ? [
          { threatType: "MALWARE", platformType: "ANY_PLATFORM", threat: { url }, cacheDuration: "300s" },
        ] : [],
        safe: Math.random() > 0.4,
      },
    };
  }

  try {
    const response = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        client: { clientId: "aegisai360", clientVersion: "1.0.0" },
        threatInfo: {
          threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
          platformTypes: ["ANY_PLATFORM"],
          threatEntryTypes: ["URL"],
          threatEntries: [{ url }],
        },
      }),
    });
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

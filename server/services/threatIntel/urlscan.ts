export async function urlscanLookup(url: string): Promise<any> {
  const apiKey = process.env.URLSCAN_API_KEY;
  if (!apiKey) {
    return {
      source: "URLScan.io",
      configured: false,
      url,
      message: "URLScan API key not configured. Set URLSCAN_API_KEY environment variable to enable live URL scanning.",
      setupUrl: "https://urlscan.io/user/signup",
      setupInstructions: "Sign up at urlscan.io, go to Settings & API, and create an API key (free tier: 50 scans/day).",
    };
  }

  try {
    const submitRes = await fetch("https://urlscan.io/api/v1/scan/", {
      method: "POST",
      headers: { "API-Key": apiKey, "Content-Type": "application/json" },
      body: JSON.stringify({ url, visibility: "private" }),
    });
    if (!submitRes.ok) {
      const errorText = await submitRes.text();
      return { source: "URLScan.io", configured: true, url, error: `API returned ${submitRes.status}: ${errorText}` };
    }
    const submitResult = await submitRes.json();
    return {
      source: "URLScan.io",
      configured: true,
      url,
      data: { uuid: submitResult.uuid, result: submitResult.result, api: submitResult.api, message: "Scan submitted. Results will be available shortly at the result URL." },
    };
  } catch (error: any) {
    return { source: "URLScan.io", configured: true, url, error: error.message };
  }
}

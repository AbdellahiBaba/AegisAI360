export async function urlscanLookup(url: string): Promise<any> {
  const apiKey = process.env.URLSCAN_API_KEY;
  if (!apiKey) {
    return {
      source: "URLScan.io",
      configured: false,
      url,
      message: "URLScan API key not configured. Set URLSCAN_API_KEY environment variable to enable live lookups.",
      stub: true,
      data: {
        verdicts: { overall: { score: Math.floor(Math.random() * 100), malicious: Math.random() > 0.7, categories: ["phishing"] } },
        page: { url, domain: new URL(url.startsWith("http") ? url : `https://${url}`).hostname, ip: "93.184.216.34", country: "US", server: "nginx", status: 200 },
        stats: { requests: Math.floor(Math.random() * 50), dataLength: Math.floor(Math.random() * 500000), encodedDataLength: Math.floor(Math.random() * 300000) },
        lists: { ips: ["93.184.216.34"], domains: ["example.com"], urls: [url] },
      },
    };
  }

  try {
    const submitRes = await fetch("https://urlscan.io/api/v1/scan/", {
      method: "POST",
      headers: { "API-Key": apiKey, "Content-Type": "application/json" },
      body: JSON.stringify({ url, visibility: "private" }),
    });
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

import Stripe from 'stripe';

let connectionSettings: any;
let cachedCredentials: { publishableKey: string; secretKey: string } | null = null;

async function fetchStripeConnection(hostname: string, xReplitToken: string, environment: string) {
  const url = new URL(`https://${hostname}/api/v2/connection`);
  url.searchParams.set('include_secrets', 'true');
  url.searchParams.set('connector_names', 'stripe');
  url.searchParams.set('environment', environment);

  const response = await fetch(url.toString(), {
    headers: {
      'Accept': 'application/json',
      'X-Replit-Token': xReplitToken
    }
  });

  const data = await response.json();
  const settings = data.items?.[0];

  if (!settings || !settings.settings?.publishable || !settings.settings?.secret) {
    return null;
  }

  return {
    publishableKey: settings.settings.publishable,
    secretKey: settings.settings.secret,
  };
}

async function getCredentials() {
  if (cachedCredentials) return cachedCredentials;

  const hostname = process.env.REPLIT_CONNECTORS_HOSTNAME;
  const xReplitToken = process.env.REPL_IDENTITY
    ? 'repl ' + process.env.REPL_IDENTITY
    : process.env.WEB_REPL_RENEWAL
      ? 'depl ' + process.env.WEB_REPL_RENEWAL
      : null;

  if (!xReplitToken) {
    throw new Error('X-Replit-Token not found for repl/depl');
  }

  const isProduction = process.env.REPLIT_DEPLOYMENT === '1';

  if (isProduction) {
    const prodCreds = await fetchStripeConnection(hostname!, xReplitToken, 'production');
    if (prodCreds) {
      console.log("Stripe: using production credentials");
      cachedCredentials = prodCreds;
      return cachedCredentials;
    }
    console.log("Stripe: production credentials not found, falling back to development");
  }

  const devCreds = await fetchStripeConnection(hostname!, xReplitToken, 'development');
  if (devCreds) {
    console.log(`Stripe: using development credentials${isProduction ? ' (fallback)' : ''}`);
    cachedCredentials = devCreds;
    return cachedCredentials;
  }

  throw new Error('Stripe connection not found in any environment');
}

export async function getUncachableStripeClient() {
  const { secretKey } = await getCredentials();
  return new Stripe(secretKey, {
    apiVersion: '2025-08-27.basil' as any,
  });
}

export async function getStripePublishableKey() {
  const { publishableKey } = await getCredentials();
  return publishableKey;
}

export async function getStripeSecretKey() {
  const { secretKey } = await getCredentials();
  return secretKey;
}

let stripeSync: any = null;

export async function getStripeSync() {
  if (!stripeSync) {
    const { StripeSync } = await import('stripe-replit-sync');
    const secretKey = await getStripeSecretKey();
    stripeSync = new StripeSync({
      poolConfig: {
        connectionString: process.env.DATABASE_URL!,
        max: 2,
      },
      stripeSecretKey: secretKey,
    });
  }
  return stripeSync;
}

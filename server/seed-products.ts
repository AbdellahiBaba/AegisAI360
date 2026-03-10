import { getUncachableStripeClient } from './stripeClient';

async function createProducts() {
  const stripe = await getUncachableStripeClient();

  const existing = await stripe.products.list({ limit: 10 });
  if (existing.data.length > 0) {
    console.log('Products already exist, skipping seed');
    return;
  }

  const starter = await stripe.products.create({
    name: 'Starter',
    description: 'Basic security monitoring for small teams. Up to 5 users, core SOC dashboard, basic alerting.',
    metadata: { plan: 'starter', maxUsers: '5', tier: 'starter' },
  });
  await stripe.prices.create({
    product: starter.id,
    unit_amount: 2900,
    currency: 'usd',
    recurring: { interval: 'month' },
  });
  console.log('Created Starter product:', starter.id);

  const professional = await stripe.products.create({
    name: 'Professional',
    description: 'Full-featured SOC platform for growing teams. Up to 25 users, AI analysis, ATT&CK mapping, forensic timeline.',
    metadata: { plan: 'professional', maxUsers: '25', tier: 'professional' },
  });
  await stripe.prices.create({
    product: professional.id,
    unit_amount: 9900,
    currency: 'usd',
    recurring: { interval: 'month' },
  });
  console.log('Created Professional product:', professional.id);

  const enterprise = await stripe.products.create({
    name: 'Enterprise',
    description: 'Unlimited security operations. Unlimited users, priority AI, advanced honeypot, custom playbooks, audit compliance.',
    metadata: { plan: 'enterprise', maxUsers: 'unlimited', tier: 'enterprise' },
  });
  await stripe.prices.create({
    product: enterprise.id,
    unit_amount: 29900,
    currency: 'usd',
    recurring: { interval: 'month' },
  });
  console.log('Created Enterprise product:', enterprise.id);

  console.log('All products created successfully');
}

createProducts().catch(console.error);

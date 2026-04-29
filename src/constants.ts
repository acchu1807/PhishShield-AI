export const TOP_SPOOFED_DOMAINS = [
  'paypal.com',
  'amazon.com',
  'microsoft.com',
  'google.com',
  'apple.com',
  'facebook.com',
  'netflix.com',
  'bankofamerica.com',
  'chase.com',
  'wellsfargo.com',
  'binance.com',
  'coinbase.com'
];

export const PHISHING_KEYWORDS = [
  'secure',
  'login',
  'update',
  'account',
  'verify',
  'banking',
  'confirm',
  'password',
  'credential',
  'support',
  'activity',
  'blocked',
  'suspended'
];

export const PREVENTION_TIPS = [
  {
    title: "Verify Source",
    description: "Always check the sender's email address and domain. Phishers often use addresses that look official but are slightly off.",
    icon: "Globe"
  },
  {
    title: "Enable MFA",
    description: "Multi-factor authentication adds a critical layer of security even if your password is stolen.",
    icon: "Lock"
  },
  {
    title: "Avoid Urgency",
    description: "Be wary of messages that pressure you to act immediately or threaten account suspension.",
    icon: "AlertTriangle"
  },
  {
    title: "Check Links",
    description: "Hover over links before clicking to see the actual destination. Never enter credentials on unfamiliar sites.",
    icon: "Key"
  }
];

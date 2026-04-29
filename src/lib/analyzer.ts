import { PHISHING_KEYWORDS } from '../constants';

export interface LexicalFeature {
  label: string;
  value: string;
  isSuspicious: boolean;
  description: string;
}

export function analyzeUrlLexical(url: string): LexicalFeature[] {
  const features: LexicalFeature[] = [];
  
  if (!url) return [];

  // 1. URL Length
  const lengthMatch = url.length > 75;
  features.push({
    label: "URL Length",
    value: `${url.length} chars`,
    isSuspicious: lengthMatch,
    description: lengthMatch ? "Extremely long URLs are often used to hide the actual domain." : "Standard length."
  });

  // 2. IP Address check
  const ipPattern = /^https?:\/\/(\d{1,3}\.){3}\d{1,3}/;
  const hasIp = ipPattern.test(url);
  features.push({
    label: "IP Usage",
    value: hasIp ? "Contains IP" : "Domain used",
    isSuspicious: hasIp,
    description: hasIp ? "Using an IP address instead of a domain name is a high risk factor." : "Uses a symbolic name."
  });

  // 3. @ symbol
  const hasAt = url.includes('@');
  features.push({
    label: "@ symbol",
    value: hasAt ? "Found" : "None",
    isSuspicious: hasAt,
    description: hasAt ? "The '@' symbol can be used to redirect the browser to another address." : "Clean."
  });

  // 4. // Redirect
  const redirectCount = (url.match(/\/\//g) || []).length;
  features.push({
    label: "Redirect Symbols",
    value: `${redirectCount}`,
    isSuspicious: redirectCount > 1,
    description: redirectCount > 1 ? "Multiple '//' indicates potential redirection tactics." : "Normal."
  });

  // 5. Special chars
  const specialChars = (url.match(/[-_=?%]/g) || []).length;
  features.push({
    label: "Complexity",
    value: `${specialChars} special chars`,
    isSuspicious: specialChars > 8,
    description: specialChars > 8 ? "High complexity might be an attempt to obscure the link." : "Low complexity."
  });

  // 6. Keywords
  const foundKeywords = PHISHING_KEYWORDS.filter(k => url.toLowerCase().includes(k));
  features.push({
    label: "Keywords",
    value: foundKeywords.length > 0 ? foundKeywords.join(', ') : "None",
    isSuspicious: foundKeywords.length > 0,
    description: foundKeywords.length > 0 ? `Contains sensitive terms: ${foundKeywords.join(', ')}` : "No common phishing keywords found."
  });

  // 7. Subdomains
  try {
    const domainPart = new URL(url).hostname;
    const dots = (domainPart.match(/\./g) || []).length;
    features.push({
      label: "Subdomains",
      value: `${dots - 1} subdomains`,
      isSuspicious: dots > 3,
      description: dots > 3 ? "Excessive subdomains are often used in phishing campaigns." : "Standard hierarchy."
    });
  } catch (e) {
    // Invalid URL
  }

  return features;
}

export function calculateBaseScore(lexical: LexicalFeature[]): number {
  if (lexical.length === 0) return 0;
  const suspiciousCount = lexical.filter(f => f.isSuspicious).length;
  return Math.min(100, (suspiciousCount / lexical.length) * 80); // Base score up to 80
}

import axios from 'axios';

export interface ThreatIntelligence {
  source: string;
  isMalicious: boolean;
  threatType?: string;
  details?: string;
}

export async function checkThreatIntelligence(url: string): Promise<ThreatIntelligence[]> {
  if (!url) return [];

  try {
    const response = await axios.post('/api/threat-intel', { url });
    return response.data;
  } catch (error) {
    console.error('Threat Intel check failed:', error);
    return [
      { source: 'Server API', isMalicious: false, details: 'Check failed or timed out.' }
    ];
  }
}

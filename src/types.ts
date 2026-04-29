export interface NetworkLog {
  url: string;
  method: string;
  status: number;
  type: string;
  size: number;
  initiator: string;
}

export interface AnalysisResult {
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH';
  score: number; // 0-100
  lexicalSignals: {
    label: string;
    value: string;
    isSuspicious: boolean;
    description: string;
  }[];
  aiAnalysis: {
    summary: string;
    markers: string[];
    recommendation: string;
  };
  visualSignals?: {
    isClone: boolean;
    similarityScore: number;
    notes: string;
    screenshot?: string; // base64
  };
  networkAnalysis?: {
    logs: NetworkLog[];
    stats: {
      totalRequests: number;
      externalTrackers: number;
      nonHttpsCount: number;
      suspiciousPostCount: number;
    };
    score: number;
  };
  threatIntel?: {
    source: string;
    isMalicious: boolean;
    threatType?: string;
    details?: string;
  }[];
}

export interface HistoryItem extends AnalysisResult {
  id: string;
  timestamp: string;
  inputType: 'URL' | 'TEXT' | 'BOTH';
  url?: string;
  text?: string;
}

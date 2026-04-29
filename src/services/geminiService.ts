import axios from 'axios';
import { AnalysisResult } from "../types";

export async function analyzePhishing(url: string, text: string): Promise<Partial<AnalysisResult>> {
  try {
    const response = await axios.post('/api/analyze', { url, text });
    const result = response.data;
    
    return {
      riskLevel: result.riskLevel,
      score: result.score,
      aiAnalysis: {
        summary: result.summary,
        markers: result.markers,
        recommendation: result.recommendation
      }
    };
  } catch (error) {
    console.error("Gemini Analysis failed:", error);
    return {
      riskLevel: 'LOW',
      score: 0,
      aiAnalysis: {
        summary: "Unable to perform AI analysis at this time.",
        markers: [],
        recommendation: "Please manually verify the source."
      }
    };
  }
}

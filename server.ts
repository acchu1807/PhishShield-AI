import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import { chromium } from 'playwright-chromium';
import { createServer as createViteServer } from 'vite';
import { GoogleGenAI } from "@google/genai";
import axios from 'axios';
import 'dotenv/config';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = Number(process.env.PORT) || 3000;

let genAIInstance: GoogleGenAI | null = null;

function getGenAI() {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey || apiKey === 'MY_GEMINI_API_KEY') {
    throw new Error('GEMINI_API_KEY is not configured or is using a placeholder. Please provide a valid Gemini API key in the secrets panel.');
  }
  if (!genAIInstance) {
    genAIInstance = new GoogleGenAI({ apiKey });
  }
  return genAIInstance;
}

app.use(express.json());

// 1. AI Analysis API
app.post('/api/analyze', async (req, res) => {
  const { url, text } = req.body;
  
  try {
    const ai = getGenAI();
    const prompt = `
      Analyze the following URL and Text for phishing attempts.
      URL: ${url || 'None provided'}
      Content (email/SMS/message): ${text || 'None provided'}

      Consider:
      1. Social engineering tactics (urgency, threats, curiosity).
      2. Data exfiltration attempts (asking for passwords, credit cards).
      3. Structural anomalies in the URL.
      4. Trust indicators (brand impersonation).

      Provide your analysis in JSON format with keys: riskLevel (LOW, MEDIUM, HIGH), score (0-100), summary, markers (array of strings), recommendation.
    `;

    const response = await ai.models.generateContent({
      model: "gemini-1.5-flash",
      contents: prompt,
      config: {
        responseMimeType: "application/json"
      }
    });
    
    const responseText = response.text || "{}";
    res.json(JSON.parse(responseText));
  } catch (error: any) {
    console.error("AI Analysis failed:", error.message);
    let message = error.message;
    if (message.includes('API key not valid')) {
      message = 'The Gemini API key provided is invalid. Please check your secrets configuration.';
    }
    res.status(500).json({ error: message });
  }
});

// 2. Threat Intelligence API
app.post('/api/threat-intel', async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: 'URL is required' });

  const results: any[] = [];
  const GOOGLE_KEY = process.env.GOOGLE_SAFE_BROWSING_API_KEY || process.env.VITE_GOOGLE_SAFE_BROWSING_API_KEY;
  const IPQS_KEY = process.env.IPQUALITYSCORE_API_KEY || process.env.VITE_IPQUALITYSCORE_API_KEY;

  // Google Safe Browsing
  if (GOOGLE_KEY) {
    try {
      const gsResponse = await axios.post(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${GOOGLE_KEY}`, {
        client: { clientId: "phishshield", clientVersion: "1.0.0" },
        threatInfo: {
          threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HAZARDOUS"],
          platformTypes: ["ANY_PLATFORM"],
          threatEntryTypes: ["URL"],
          threatEntries: [{ url }]
        }
      });
      if (gsResponse.data && gsResponse.data.matches) {
        results.push({
          source: 'Google Safe Browsing',
          isMalicious: true,
          threatType: gsResponse.data.matches[0].threatType,
          details: 'Flagged by Google Safe Browsing.'
        });
      } else {
        results.push({ source: 'Google Safe Browsing', isMalicious: false, details: 'Clean.' });
      }
    } catch (e: any) {
      console.error('Google Safe Browsing failed:', e.message);
      let errorMsg = e.message;
      if (e.response) {
        console.error('Safe Browsing Error details:', JSON.stringify(e.response.data));
        if (e.response.status === 403) {
          errorMsg = 'API Key blocked or Safe Browsing API not enabled for this project.';
        } else if (e.response.data?.error?.message) {
          errorMsg = e.response.data.error.message;
        }
      }
      results.push({ 
        source: 'Google Safe Browsing', 
        isMalicious: false, 
        details: 'Check failed: ' + errorMsg
      });
    }
  }

  // IPQualityScore
  if (IPQS_KEY) {
    try {
      const ipqsRes = await axios.get(`https://www.ipqualityscore.com/api/json/url/${IPQS_KEY}/${encodeURIComponent(url)}`);
      if (ipqsRes.data && ipqsRes.data.success) {
        const isMalicious = ipqsRes.data.unsafe || ipqsRes.data.phishing || ipqsRes.data.malware;
        results.push({
          source: 'IPQualityScore',
          isMalicious,
          threatType: isMalicious ? 'Malicious' : 'Clean',
          details: `Risk Score: ${ipqsRes.data.risk_score}`
        });
      }
    } catch (e: any) {
      console.error('IPQS failed:', e.message);
      results.push({ source: 'IPQualityScore', isMalicious: false, details: 'Check failed: ' + e.message });
    }
  }

  res.json(results);
});

// 3. Network Inspection Logic
app.post('/api/inspect', async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: 'URL is required' });

  let browser;
  try {
    browser = await chromium.launch({ headless: true });
    const context = await browser.newContext();
    const page = await context.newPage();
    
    // Preliminary Availability Check
    try {
      const response = await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 10000 });
      if (!response || !response.ok()) {
         const status = response ? response.status() : 'No Response';
         await browser.close();
         return res.json({ 
           availability: { status, error: 'Non-200 status or unreachable', ok: false },
           score: 100 // High risk for dead links/errors
         });
      }
      
      const content = await page.content();
      if (content.includes('404 Not Found') || (await page.title()) === '') {
         await browser.close();
         return res.json({ 
           availability: { status: 'Loaded but invalid', error: 'Empty or 404 content', ok: false },
           score: 100
         });
      }
    } catch (e: any) {
      await browser.close();
      return res.json({ 
        availability: { status: 'Timeout/Error', error: e.message || 'Site unreachable', ok: false },
        score: 100
      });
    }

    const logs: any[] = [];
    const stats = {
      totalRequests: 0,
      externalTrackers: 0,
      nonHttpsCount: 0,
      suspiciousPostCount: 0
    };

    page.on('request', request => {
      const u = request.url();
      stats.totalRequests++;
      
      if (!u.startsWith('https://')) stats.nonHttpsCount++;
      if (u.includes('track') || u.includes('pixel') || u.includes('analytics')) stats.externalTrackers++;
      if (request.method() === 'POST' && !u.includes(new URL(url).hostname)) stats.suspiciousPostCount++;

      logs.push({
        url: u,
        method: request.method(),
        status: 0,
        type: request.resourceType(),
        size: 0,
        initiator: 'network'
      });
    });

    page.on('response', response => {
      const log = logs.find(l => l.url === response.url());
      if (log) {
        log.status = response.status();
        const headers = response.headers();
        log.size = parseInt(headers['content-length'] || '0');
      }
    });

    await page.goto(url, { waitUntil: 'networkidle', timeout: 15000 });
    
    // Minimal interaction as requested
    const loginButtons = await page.$$('button:has-text("login"), button:has-text("sign in")');
    if (loginButtons.length > 0) {
      // Just hover to trigger any dynamic loads
      await loginButtons[0].hover();
    }

    const screenshot = await page.screenshot({ fullPage: true, type: 'jpeg', quality: 50 });
    
    // Calculate network score (30% weight in UI, but here we return raw component)
    // Non-HTTPS (20pts), trackers>5 (15pts), POST to external (25pts)
    let networkScore = 0;
    if (stats.nonHttpsCount > 0) networkScore += 20;
    if (stats.externalTrackers > 5) networkScore += 15;
    if (stats.suspiciousPostCount > 0) networkScore += 25;

    await browser.close();

    res.json({
      logs: logs.slice(0, 50),
      stats,
      score: networkScore,
      screenshot: screenshot.toString('base64')
    });

  } catch (error: any) {
    if (browser) await browser.close();
    console.error('Inspection Error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', engine: 'PhishShield AI', version: '2.5.0' });
});

async function startServer() {
  // Production: Serve static files from the dist folder
  if (process.env.NODE_ENV === 'production') {
    app.use(express.static(path.join(__dirname, 'dist')));
    
    app.get('*', (req, res) => {
      res.sendFile(path.join(__dirname, 'dist', 'index.html'));
    });
  } else {
    // In dev, the Vite dev server handles requests
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server is running on http://0.0.0.0:${PORT}`);
  });
}

startServer();

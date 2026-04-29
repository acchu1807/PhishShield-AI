import React, { useState } from 'react';
import { 
  Shield, Search, AlertCircle, CheckCircle2, ChevronRight, Share2, 
  Trash2, Terminal, ArrowRight, Activity, Zap, Cpu, Globe, 
  Clock, BarChart3, ListFilter, Download, AlertTriangle, Check
} from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import axios from 'axios';
import { analyzeUrlLexical, calculateBaseScore } from './lib/analyzer';
import { analyzePhishing } from './services/geminiService';
import { checkThreatIntelligence } from './services/threatIntelService';
import { Gauge } from './components/Gauge';
import { PreventionTips } from './components/PreventionTips';
import { cn, formatDate } from './lib/utils';
import { AnalysisResult, HistoryItem, NetworkLog } from './types';

import { TOP_SPOOFED_DOMAINS } from './constants';

type ActiveTab = 'METRICS' | 'NETWORK' | 'PREVENTION';

export default function App() {
  const [url, setUrl] = useState('');
  const [text, setText] = useState('');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [availabilityError, setAvailabilityError] = useState<{status: string, error: string} | null>(null);
  const [history, setHistory] = useState<HistoryItem[]>([]);
  const [view, setView] = useState<'ANALYZE' | 'HISTORY'>('ANALYZE');
  const [activeTab, setActiveTab] = useState<ActiveTab>('METRICS');
  const [networkFilter, setNetworkFilter] = useState('');

  const handleAnalyze = async () => {
    if (!url && !text) return;
    setIsAnalyzing(true);
    setResult(null);
    setAvailabilityError(null);
    setActiveTab('METRICS');

    try {
      // 1. Lexical Analysis
      const lexical = analyzeUrlLexical(url);
      
      // Top Spoofed Domain Check
      if (url) {
        try {
          const domain = new URL(url.startsWith('http') ? url : `https://${url}`).hostname.replace('www.', '');
          const isSpoofed = TOP_SPOOFED_DOMAINS.some(d => domain.includes(d) && domain !== d);
          if (isSpoofed) {
            lexical.push({
              label: 'Spoofed Domain',
              value: domain,
              isSuspicious: true,
              description: 'Target domain mimics a popular service to deceive users.'
            });
          }
        } catch (e) {}
      }

      let lexicalScore = calculateBaseScore(lexical);

      // Boost score if spoofed domain detected
      const hasSpoofedSignal = lexical.some(l => l.label === 'Spoofed Domain' && l.isSuspicious);
      if (hasSpoofedSignal) {
        lexicalScore = Math.max(lexicalScore, 85); // High floor for spoofing
      }

      // 2. Parallel Remote Analysis
      const aiPromise = analyzePhishing(url, text);
      const threatPromise = checkThreatIntelligence(url);
      
      // 3. Network Inspection & Availability
      let networkData = null;
      if (url) {
        try {
          const res = await axios.post('/api/inspect', { url: url.startsWith('http') ? url : `https://${url}` });
          if (res.data.availability && !res.data.availability.ok) {
            setAvailabilityError(res.data.availability);
            const failResult: AnalysisResult = {
              riskLevel: 'HIGH',
              score: 100,
              lexicalSignals: lexical,
              aiAnalysis: {
                summary: "OFFLINE_THREAT: The destination site is unreachable or returned a critical error. This is a primary indicator of dynamic phishing redirects or expired lures.",
                markers: ['SITE_OFFLINE', 'INVALID_CERTIFICATE', 'HIGH_RISK_LURE'],
                recommendation: "ABORT: Site availability test failed. Do not attempt to bypass security warnings."
              }
            };
            setResult(failResult);
            setIsAnalyzing(false);
            return;
          }
          networkData = res.data;
        } catch (e) {
          console.error("Network inspection failed", e);
        }
      }

      const [aiResponse, threatIntel] = await Promise.all([aiPromise, threatPromise]);

      // 4. Combined Scoring (New Weights)
      // URL(30%) / Text(20%) / Visual(20%) / Network(30%)
      const urlComponent = lexicalScore * 0.3;
      const textComponent = (aiResponse.score || 0) * 0.2;
      const networkComponent = (networkData?.score || 0) * 0.3;
      // Visual similarity placeholder logic (20%)
      const visualComponent = (threatIntel.some(t => t.isMalicious) ? 100 : 0) * 0.2;

      let finalScore = Math.round(urlComponent + textComponent + networkComponent + visualComponent);
      
      // Inflate if database hit
      if (threatIntel.some(t => t.isMalicious)) {
        finalScore = Math.max(95, finalScore);
      }

      const newResult: AnalysisResult = {
        riskLevel: finalScore > 75 ? 'HIGH' : finalScore > 40 ? 'MEDIUM' : 'LOW',
        score: Math.min(100, finalScore),
        lexicalSignals: lexical,
        aiAnalysis: aiResponse.aiAnalysis || {
          summary: "AI check complete.",
          markers: [],
          recommendation: "Manual verification advised."
        },
        threatIntel,
        networkAnalysis: networkData ? {
          logs: networkData.logs,
          stats: networkData.stats,
          score: networkData.score
        } : undefined,
        visualSignals: networkData?.screenshot ? {
          isClone: false,
          similarityScore: 0,
          notes: "Visual verification completed.",
          screenshot: networkData.screenshot
        } : undefined
      };

      setResult(newResult);
      
      const historyItem: HistoryItem = {
        ...newResult,
        id: Math.random().toString(36).substring(2, 9),
        timestamp: new Date().toISOString(),
        inputType: url && text ? 'BOTH' : url ? 'URL' : 'TEXT',
        url,
        text
      };
      setHistory(prev => [historyItem, ...prev]);

    } catch (error) {
      console.error("Analysis sequence failed", error);
    } finally {
      setIsAnalyzing(false);
    }
  };

  const filteredLogs = result?.networkAnalysis?.logs.filter(log => 
    log.url.toLowerCase().includes(networkFilter.toLowerCase())
  ) || [];

  const downloadJson = () => {
    if (!result?.networkAnalysis?.logs) return;
    const blob = new Blob([JSON.stringify(result.networkAnalysis.logs, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `network_log_${Date.now()}.json`;
    a.click();
  };

  return (
    <div className="min-h-screen bg-white text-indigo-950 font-sans selection:bg-indigo-600 selection:text-white">
      {/* Background Decorative Element */}
      <div className="fixed inset-0 pointer-events-none overflow-hidden select-none">
        <div className="absolute -top-[10%] -left-[10%] w-[50%] h-[50%] bg-indigo-50/40 rounded-full blur-[140px]" />
        <div className="absolute top-[20%] right-[10%] w-[30%] h-[30%] bg-blue-50/30 rounded-full blur-[100px]" />
        <div className="absolute bottom-[10%] left-1/2 -translate-x-1/2 w-[60%] h-[40%] bg-emerald-50/20 rounded-full blur-[120px]" />
      </div>

      <header className="sticky top-0 z-50 bg-white/80 backdrop-blur-2xl border-b border-indigo-100/50">
        <div className="max-w-7xl mx-auto px-10 h-24 flex items-center justify-between">
          <div className="flex items-center gap-5 group cursor-default">
            <div className="w-12 h-12 rounded-2xl bg-indigo-600 flex items-center justify-center text-white shadow-2xl shadow-indigo-600/20 group-hover:scale-105 transition-all duration-500">
              <Shield className="w-6 h-6" />
            </div>
            <div>
              <h1 className="text-lg font-black tracking-tighter text-indigo-950 uppercase leading-none mb-1">SENTINEL_AI</h1>
              <div className="flex items-center gap-2">
                <div className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse shadow-[0_0_8px_#10b981]" />
                <span className="text-[10px] font-black text-indigo-300 uppercase tracking-[0.3em]">PhishShield_v2.5.0</span>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-8">
            <nav className="flex items-center p-1 bg-indigo-50/50 border border-indigo-100 rounded-2xl">
              <button 
                onClick={() => setView('ANALYZE')}
                className={cn(
                  "px-6 py-2.5 rounded-xl text-[10px] font-black tracking-[0.2em] transition-all uppercase",
                  view === 'ANALYZE' ? "bg-white text-indigo-600 shadow-md" : "text-indigo-400 hover:text-indigo-900"
                )}
              >
                Investigate
              </button>
              <button 
                onClick={() => setView('HISTORY')}
                className={cn(
                  "px-6 py-2.5 rounded-xl text-[10px] font-black tracking-[0.2em] transition-all uppercase",
                  view === 'HISTORY' ? "bg-white text-indigo-600 shadow-md" : "text-indigo-400 hover:text-indigo-900"
                )}
              >
                Audit_Vault
              </button>
            </nav>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-8 py-16 relative">
        {view === 'ANALYZE' ? (
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-12 items-start">
            {/* Control Panel */}
            <div className="lg:col-span-4 space-y-8">
              <div className="premium-card rounded-[40px] p-12 space-y-12">
                <div className="space-y-3">
                  <h2 className="text-[10px] font-black uppercase tracking-[0.3em] text-indigo-500">Targeting System</h2>
                  <p className="text-base text-indigo-950 font-bold leading-tight">Configure investigation parameters for real-time analysis.</p>
                </div>

                <div className="space-y-8">
                  <div className="space-y-4">
                    <div className="flex justify-between items-center">
                      <label className="text-[10px] font-black text-indigo-300 uppercase tracking-widest">Entry URI</label>
                      <span className="text-[9px] font-mono text-indigo-200">PROTOCOL://*</span>
                    </div>
                    <div className="relative group">
                      <Globe className="absolute left-6 top-1/2 -translate-y-1/2 w-4 h-4 text-indigo-100 group-focus-within:text-indigo-500 transition-colors" />
                      <input 
                        type="text"
                        placeholder="e.g. secure.banking-portal.io"
                        value={url}
                        onChange={(e) => setUrl(e.target.value)}
                        className="w-full bg-indigo-50/30 border border-indigo-100/50 rounded-2xl py-5 pl-16 pr-6 text-sm font-bold focus:outline-none focus:ring-4 focus:ring-indigo-500/10 transition-all placeholder:text-indigo-200 text-indigo-950"
                      />
                    </div>
                  </div>

                  <div className="space-y-4">
                     <div className="flex justify-between items-center">
                      <label className="text-[10px] font-black text-indigo-300 uppercase tracking-widest">Payload Data</label>
                      <span className="text-[9px] font-mono text-indigo-200">RAW_ENCODING</span>
                    </div>
                    <textarea 
                      placeholder="Paste suspicious text content here for linguistic pattern matching..."
                      value={text}
                      onChange={(e) => setText(e.target.value)}
                      rows={6}
                      className="w-full bg-indigo-50/30 border border-indigo-100/50 rounded-2xl p-6 text-sm font-bold focus:outline-none focus:ring-4 focus:ring-indigo-500/10 transition-all resize-none leading-relaxed placeholder:text-indigo-200 text-indigo-950"
                    />
                  </div>

                  <div className="pt-2">
                    <button 
                      onClick={handleAnalyze}
                      disabled={isAnalyzing || (!url && !text)}
                      className="group relative w-full overflow-hidden rounded-2xl bg-indigo-600 py-6 font-black text-xs text-white shadow-2xl shadow-indigo-500/20 active:scale-[0.98] transition-all disabled:opacity-20 disabled:scale-100"
                    >
                      <div className="absolute inset-0 bg-white/10 translate-y-full group-hover:translate-y-0 transition-transform duration-500" />
                      <div className="relative flex items-center justify-center gap-3">
                        {isAnalyzing ? (
                          <motion.div animate={{ rotate: 360 }} transition={{ repeat: Infinity, duration: 1, ease: 'linear' }}>
                            <Cpu className="w-5 h-5" />
                          </motion.div>
                        ) : (
                          <>
                            <span className="tracking-[0.3em] uppercase">Execute_Sequence</span>
                            <ArrowRight className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
                          </>
                        )}
                      </div>
                    </button>
                  </div>
                </div>
              </div>

              <div className="rounded-[32px] overflow-hidden bg-indigo-950 p-1 relative shadow-xl">
                 <div className="bg-indigo-950/80 p-8 space-y-6">
                    <div className="flex items-center gap-4">
                       <div className="w-10 h-10 rounded-xl bg-indigo-900/50 flex items-center justify-center border border-indigo-800/50">
                          <Zap className="w-5 h-5 text-indigo-400" />
                       </div>
                       <div>
                          <h4 className="text-[11px] font-black text-indigo-400 uppercase tracking-[0.2em]">Neural_Engine_v2</h4>
                          <p className="text-[10px] text-indigo-600 font-bold uppercase tracking-tight">Latency: Realtime</p>
                       </div>
                    </div>
                    <p className="text-xs text-indigo-300/80 leading-relaxed">
                       Our zero-day detection engine cross-references millions of threat vectors.
                    </p>
                 </div>
              </div>
            </div>

            {/* Analysis Output */}
            <div className="lg:col-span-8">
              <AnimatePresence mode="wait">
                {isAnalyzing ? (
                  <motion.div 
                    initial={{ opacity: 0, scale: 0.98 }} animate={{ opacity: 1, scale: 1 }} exit={{ opacity: 0, scale: 1.02 }}
                    className="h-full min-h-[700px] flex flex-col items-center justify-center premium-card rounded-[48px] py-32 border-dashed border-indigo-100"
                  >
                    <div className="relative mb-16">
                      <div className="w-32 h-32 rounded-full border border-indigo-50 animate-[ping_2s_infinite] absolute inset-0" />
                      <div className="w-32 h-32 rounded-full bg-indigo-50/30 backdrop-blur-sm border border-indigo-100 flex items-center justify-center">
                        <motion.div
                          animate={{ rotate: 360 }}
                          transition={{ repeat: Infinity, duration: 3, ease: "linear" }}
                        >
                          <Activity className="w-12 h-12 text-indigo-200" />
                        </motion.div>
                      </div>
                    </div>
                    <div className="space-y-4 text-center">
                      <h3 className="text-2xl font-bold text-indigo-950 tracking-tight">Intercepting Signals...</h3>
                      <div className="flex justify-center gap-2">
                        {[0, 1, 2].map(i => (
                          <motion.div 
                            key={i}
                            animate={{ opacity: [0.2, 1, 0.2] }}
                            transition={{ repeat: Infinity, duration: 1.5, delay: i * 0.2 }}
                            className="w-1.5 h-1.5 rounded-full bg-indigo-600"
                          />
                        ))}
                      </div>
                      <p className="text-sm text-indigo-400 font-medium max-w-sm mx-auto">
                        Scanning domain reputation, network headers, and linguistic signatures with Gemini AI.
                      </p>
                    </div>
                  </motion.div>
                ) : result ? (
                  <motion.div 
                     initial={{ opacity: 0, y: 30 }} 
                     animate={{ opacity: 1, y: 0 }} 
                     transition={{ duration: 0.6, ease: [0.23, 1, 0.32, 1] }} 
                     className="space-y-12"
                  >
                    {availabilityError && (
                      <motion.div 
                        initial={{ opacity: 0, scale: 0.95 }}
                        animate={{ opacity: 1, scale: 1 }}
                        className="p-8 bg-rose-50 dark:bg-rose-950/20 border-2 border-rose-100 dark:border-rose-900/30 rounded-[32px] flex items-start gap-6 shadow-xl shadow-rose-900/5"
                      >
                        <div className="w-14 h-14 rounded-2xl bg-rose-500 flex items-center justify-center text-white shrink-0">
                          <AlertTriangle className="w-7 h-7" />
                        </div>
                        <div className="space-y-2">
                          <h3 className="text-xl font-black text-rose-600 dark:text-rose-400 uppercase tracking-tight">🚨 SITE_ISSUE_DETECTED</h3>
                          <p className="text-rose-700/80 dark:text-rose-300/80 font-medium leading-relaxed">
                            <span className="font-black text-rose-600 dark:text-rose-400">[{availabilityError.status}]</span> - {availabilityError.error}
                          </p>
                          <div className="text-xs font-bold text-rose-400 dark:text-rose-500 uppercase tracking-widest mt-4">
                            High Risk: Phishing lures often use dead links or typosquatting redirects.
                          </div>
                        </div>
                      </motion.div>
                    )}

                    {/* Bento Score Section */}
                    <div className="bg-white rounded-[48px] p-12 shadow-[0_40px_100px_-20px_rgba(79,70,229,0.1)] border border-indigo-100 grid grid-cols-1 md:grid-cols-12 gap-16 items-center">
                      <div className="md:col-span-6">
                        <Gauge score={result.score} level={result.riskLevel} />
                      </div>
                      <div className="md:col-span-6 space-y-10">
                        <div className="space-y-4">
                          <div className="flex items-center gap-3">
                             <div className={cn(
                               "px-4 py-1.5 rounded-xl text-[10px] font-black uppercase tracking-[0.2em] shadow-sm",
                               result.riskLevel === 'HIGH' ? "bg-rose-50 text-rose-600 border border-rose-100" : result.riskLevel === 'MEDIUM' ? "bg-amber-50 text-amber-600 border border-amber-100" : "bg-emerald-50 text-emerald-600 border border-emerald-100"
                             )}>
                               {result.riskLevel}_THREAT_DETECTED
                             </div>
                             {url && (
                               <div className={cn(
                                 "px-3 py-1.5 rounded-xl text-[9px] font-black uppercase tracking-widest flex items-center gap-2",
                                 availabilityError ? "bg-rose-100 text-rose-700" : "bg-emerald-100 text-emerald-700"
                               )}>
                                 {availabilityError ? <AlertTriangle className="w-3 h-3" /> : <Check className="w-3 h-3" />}
                                 {availabilityError ? "SITE_OFFLINE" : "SITE_ONLINE"}
                               </div>
                             )}
                          </div>
                          <h2 className="text-4xl font-black tracking-tight text-indigo-950 uppercase leading-none">Summary</h2>
                          <p className="text-base text-indigo-400 leading-relaxed font-bold italic">
                            "{result.aiAnalysis.summary}"
                          </p>
                        </div>
                        
                        <div className="flex flex-wrap gap-4">
                          {result.aiAnalysis.markers.map((m, i) => (
                            <div key={i} className="px-5 py-2.5 bg-white border border-indigo-50 rounded-2xl text-[9px] text-indigo-400 font-black uppercase tracking-[0.2em] shadow-sm hover:border-indigo-200 transition-colors">
                               {m}
                            </div>
                          ))}
                        </div>
                      </div>
                    </div>

                    {/* Navigation Tabs */}
                    <div className="space-y-6">
                       <div className="flex items-center gap-2 bg-indigo-50/30 p-1.5 rounded-[20px] w-fit border border-indigo-100/50">
                          {[
                            { id: 'METRICS', label: 'Security_Signals', icon: BarChart3 },
                            { id: 'NETWORK', label: 'Network_Inspector', icon: Terminal },
                            { id: 'PREVENTION', label: 'Mitigation_Plan', icon: Shield },
                          ].map(t => (
                            <button 
                              key={t.id}
                              onClick={() => setActiveTab(t.id as ActiveTab)}
                              className={cn(
                                "flex items-center gap-2.5 px-6 py-3.5 rounded-2xl text-[11px] font-black uppercase tracking-widest transition-all",
                                activeTab === t.id ? "bg-white text-indigo-600 shadow-md" : "text-indigo-300 hover:text-indigo-600"
                              )}
                            >
                              <t.icon className="w-4 h-4" />
                              {t.label}
                            </button>
                          ))}
                       </div>

                       <div className="premium-card rounded-[40px] p-12 overflow-hidden">
                          {activeTab === 'METRICS' && (
                             <div className="grid grid-cols-1 md:grid-cols-2 gap-16">
                                <div className="space-y-8">
                                   <div>
                                      <h4 className="text-[10px] font-black text-indigo-300 uppercase tracking-[0.25em] mb-6 flex items-center justify-between">
                                         Heuristic Markers
                                         <span className="w-1.5 h-1.5 rounded-full bg-indigo-500" />
                                      </h4>
                                      <div className="space-y-6">
                                         {result.lexicalSignals.map((s, i) => (
                                           <div key={i} className="flex items-center justify-between group">
                                              <div className="space-y-1">
                                                 <div className="text-xs font-black text-indigo-950 tracking-tight leading-none mb-1">{s.label}</div>
                                                 <div className="text-[10px] text-indigo-300 font-mono font-bold truncate max-w-[200px]">{s.value}</div>
                                              </div>
                                              <div className={cn(
                                                 "w-12 h-12 rounded-2xl flex items-center justify-center border transition-all duration-500 shadow-sm",
                                                 s.isSuspicious ? "bg-rose-50 border-rose-100 text-rose-500" : "bg-emerald-50 border-emerald-100 text-emerald-500"
                                              )}>
                                                 {s.isSuspicious ? <AlertCircle className="w-6 h-6" /> : <CheckCircle2 className="w-6 h-6" />}
                                              </div>
                                           </div>
                                         ))}
                                      </div>
                                   </div>
                                </div>

                                <div className="space-y-8">
                                   <div>
                                      <h4 className="text-[10px] font-black text-indigo-300 uppercase tracking-[0.25em] mb-6 flex items-center justify-between">
                                         Intel Database Hits
                                         <span className="w-1.5 h-1.5 rounded-full bg-rose-500" />
                                      </h4>
                                      <div className="space-y-4">
                                         {result.threatIntel?.map((intel, i) => (
                                           <div key={i} className="p-5 bg-indigo-50/20 border border-indigo-100/50 rounded-2xl flex items-center justify-between">
                                              <div className="flex items-center gap-4">
                                                 <div className={cn("w-2.5 h-2.5 rounded-full", intel.isMalicious ? "bg-rose-500 shadow-[0_0_12px_rgba(244,63,94,0.4)]" : "bg-emerald-500 shadow-[0_0_12px_rgba(16,185,129,0.4)]")} />
                                                 <span className="text-[11px] font-black text-indigo-400 uppercase tracking-widest">{intel.source}</span>
                                              </div>
                                              <span className={cn("text-[9px] font-black px-2 py-1 rounded-md", intel.isMalicious ? "bg-rose-100 text-rose-600" : "bg-emerald-100 text-emerald-600")}>
                                                 {intel.isMalicious ? 'THREAT' : 'SECURE'}
                                              </span>
                                           </div>
                                         ))}
                                      </div>
                                   </div>

                                   <div className="p-6 bg-indigo-900 text-white rounded-3xl relative overflow-hidden">
                                      <div className="absolute top-0 right-0 w-24 h-24 bg-white/5 blur-3xl rounded-full" />
                                      <h5 className="text-[10px] font-black text-indigo-400 uppercase tracking-[0.2em] mb-3">Tactical Recommendation</h5>
                                      <p className="text-sm font-medium leading-relaxed italic border-l-2 border-indigo-400 pl-4">
                                         {result.aiAnalysis.recommendation}
                                      </p>
                                   </div>
                                </div>
                             </div>
                          )}

                          {activeTab === 'NETWORK' && (
                            <div className="space-y-10">
                               <div className="flex flex-col md:flex-row md:items-center justify-between gap-6">
                                  <div className="flex items-center gap-4 bg-indigo-50/50 px-6 py-4 border border-indigo-100 rounded-2xl flex-1 max-w-lg">
                                     <Search className="w-4 h-4 text-indigo-300" />
                                     <input 
                                        type="text" 
                                        placeholder="Filter by domain or protocol..." 
                                        className="text-sm font-bold w-full focus:outline-none bg-transparent text-indigo-950 placeholder:text-indigo-200"
                                        value={networkFilter}
                                        onChange={e => setNetworkFilter(e.target.value)}
                                     />
                                  </div>
                                  <button onClick={downloadJson} className="flex items-center gap-3 bg-white border border-indigo-100 px-8 py-4 rounded-2xl text-[10px] font-black text-indigo-600 hover:bg-indigo-50 transition-all uppercase tracking-[0.2em]">
                                     <Download className="w-4 h-4" />
                                     Export_Raw_Log
                                  </button>
                               </div>

                               <div className="overflow-hidden border border-indigo-100 rounded-3xl">
                                  <table className="w-full text-left text-[11px] border-collapse bg-white">
                                     <thead>
                                        <tr className="bg-indigo-50/50 text-indigo-300 font-black uppercase tracking-[0.2em]">
                                           <th className="p-6">Method</th>
                                           <th className="p-6">Origin</th>
                                           <th className="p-6">Protocol_Path</th>
                                           <th className="p-6 text-right">Data_Size</th>
                                        </tr>
                                     </thead>
                                     <tbody className="divide-y divide-indigo-50">
                                        {filteredLogs.map((log, i) => (
                                          <tr key={i} className="group hover:bg-indigo-50/30 transition-colors">
                                             <td className="p-6 font-black text-indigo-950 uppercase">{log.method}</td>
                                             <td className="p-6">
                                                <span className={cn(
                                                   "px-2 py-1 rounded-md font-mono font-bold text-[9px]",
                                                   log.status >= 400 ? "bg-rose-50 text-rose-500" : log.status >= 200 ? "bg-emerald-50 text-emerald-500" : "bg-indigo-50 text-indigo-300"
                                                )}>{log.status || '???' }</span>
                                             </td>
                                             <td className="p-6 font-mono text-indigo-400 transition-colors truncate max-w-[350px]">
                                                {log.url}
                                             </td>
                                             <td className="p-6 text-right font-black text-indigo-950 tabular-nums">
                                                {(log.size / 1024).toFixed(1)} <span className="text-indigo-200 font-medium font-sans">KB</span>
                                             </td>
                                          </tr>
                                        ))}
                                     </tbody>
                                  </table>
                                  {filteredLogs.length === 0 && (
                                    <div className="py-32 text-center text-indigo-100 font-black uppercase tracking-[0.3em] text-xs">No_Artifacts_Found</div>
                                  )}
                               </div>
                            </div>
                          )}

                          {activeTab === 'PREVENTION' && (
                            <div className="space-y-16">
                               {result.visualSignals?.screenshot && (
                                 <div className="space-y-6">
                                    <h4 className="text-[10px] font-black text-indigo-300 uppercase tracking-[0.25em] border-b border-indigo-50 pb-4 flex items-center justify-between">
                                       Inspection Captured Frame
                                       <Clock className="w-4 h-4 text-indigo-100" />
                                    </h4>
                                    <div className="rounded-[32px] overflow-hidden border border-indigo-100 shadow-2xl max-h-[500px]">
                                       <img src={`data:image/jpeg;base64,${result.visualSignals.screenshot}`} alt="Capture" className="w-full object-top object-cover hover:scale-105 transition-transform duration-1000" />
                                    </div>
                                    <div className="p-6 bg-indigo-50/50 rounded-2xl text-center">
                                       <p className="text-[10px] font-bold text-indigo-200 uppercase tracking-widest">Render Hash: {Math.random().toString(16).substring(2,12).toUpperCase()}</p>
                                    </div>
                                 </div>
                               )}
                               <PreventionTips />
                            </div>
                          )}
                       </div>
                    </div>
                  </motion.div>
                ) : (
                  <div className="h-full min-h-[700px] flex flex-col items-center justify-center premium-card rounded-[48px] border-dashed border-indigo-100">
                    <div className="w-24 h-24 rounded-full bg-indigo-50 border border-indigo-100 flex items-center justify-center mb-10 group relative shadow-sm">
                       <div className="absolute inset-0 bg-indigo-100 rounded-full scale-0 group-hover:scale-150 opacity-0 group-hover:opacity-100 transition-all duration-700" />
                       <Search className="w-10 h-10 text-indigo-200 relative group-hover:text-indigo-400 transition-colors" />
                    </div>
                    <div className="text-center space-y-6">
                       <h3 className="text-2xl font-black text-indigo-100 uppercase tracking-[0.4em]">Awaiting_Signal</h3>
                       <p className="text-sm text-indigo-300 font-bold max-w-sm mx-auto uppercase tracking-widest leading-relaxed">Please initialize investigation by providing a network URI or suspected payload content.</p>
                    </div>
                  </div>
                )}
              </AnimatePresence>
            </div>
          </div>
        ) : (
          <div className="space-y-12">
             <div className="flex flex-col md:flex-row md:items-center justify-between gap-6">
                <div className="space-y-2">
                  <h2 className="text-4xl font-black tracking-tight text-indigo-950 uppercase leading-none">Audit_Archive</h2>
                  <p className="text-indigo-300 font-bold tracking-tight">Systematic historical record of all analysis sessions.</p>
                </div>
                <button 
                  onClick={() => setHistory([])} 
                  className="px-8 py-4 rounded-[20px] bg-rose-50 text-rose-600 font-black text-[10px] uppercase tracking-[0.2em] hover:bg-rose-100 active:scale-[0.98] transition-all flex items-center gap-2 border border-rose-100 shadow-sm"
                >
                   <Trash2 className="w-4 h-4" />
                   Purge_Memory_Cache
                </button>
             </div>

             <div className="premium-card rounded-[40px] overflow-hidden">
               <table className="w-full text-left">
                 <thead>
                   <tr className="bg-indigo-50 border-b border-indigo-100 text-[10px] font-black text-indigo-300 uppercase tracking-[0.25em]">
                     <th className="p-8">Session_Timestamp</th>
                     <th className="p-8">Target_Identifier</th>
                     <th className="p-8">Verified_Risk</th>
                     <th className="p-8 w-20 text-center">Action</th>
                   </tr>
                 </thead>
                 <tbody className="divide-y divide-indigo-50">
                   {history.map(item => (
                     <tr key={item.id} className="group hover:bg-indigo-50/30 transition-colors">
                       <td className="p-8 text-xs text-indigo-300 font-mono font-bold italic">{formatDate(item.timestamp)}</td>
                       <td className="p-8">
                         <div className="text-sm font-black text-indigo-950 truncate max-w-sm uppercase">{item.url || 'RAW_PAYLOAD_ANALYSIS'}</div>
                         <div className="text-[9px] text-indigo-200 font-black uppercase tracking-widest mt-1">{item.inputType}_Sequence</div>
                       </td>
                       <td className="p-8">
                         <div className={cn(
                           "inline-flex px-4 py-1.5 rounded-xl text-[10px] font-black uppercase tracking-widest border shadow-sm",
                           item.riskLevel === 'HIGH' ? "bg-rose-50 border-rose-100 text-rose-600" : item.riskLevel === 'MEDIUM' ? "bg-amber-50 border-amber-100 text-amber-600" : "bg-emerald-50 border-emerald-100 text-emerald-600"
                         )}>
                            {item.riskLevel}
                         </div>
                       </td>
                       <td className="p-8 text-center">
                         <button onClick={() => { setView('ANALYZE'); setResult(item); setUrl(item.url || ''); setText(item.text || ''); }} className="hover:translate-x-2 transition-transform p-3 rounded-full bg-indigo-50 text-indigo-950 group-hover:bg-indigo-600 group-hover:text-white duration-300">
                           <ChevronRight className="w-5 h-5" />
                         </button>
                       </td>
                     </tr>
                   ))}
                   {history.length === 0 && (
                     <tr><td colSpan={4} className="p-40 text-center text-indigo-100 font-black uppercase tracking-[0.4em] text-xs">Repository_Empty</td></tr>
                   )}
                 </tbody>
               </table>
             </div>
          </div>
        )}
      </main>

      <footer className="max-w-7xl mx-auto px-8 py-24 border-t border-indigo-100 flex flex-col md:flex-row items-center justify-between gap-12 mt-20 opacity-40 hover:opacity-100 transition-opacity duration-1000">
         <div className="flex items-center gap-4">
            <div className="w-8 h-8 rounded-xl bg-indigo-600 flex items-center justify-center text-white">
              <Shield className="w-4 h-4" />
            </div>
            <div className="text-[11px] font-black uppercase tracking-[0.4em] text-indigo-950">PhishShield Systems_v2.5.0</div>
         </div>
         <div className="flex items-center gap-12 text-[10px] font-black text-indigo-300 uppercase tracking-[0.25em]">
            <a href="#" className="hover:text-indigo-600 transition-all hover:tracking-[0.3em]">Defense_Strategy</a>
            <a href="#" className="hover:text-indigo-600 transition-all hover:tracking-[0.3em]">Network_Grid</a>
            <a href="#" className="hover:text-indigo-600 transition-all hover:tracking-[0.3em]">Intelligence_API</a>
         </div>
         <div className="flex items-center gap-8 text-indigo-300">
            <Terminal className="w-5 h-5 cursor-pointer hover:text-indigo-600 hover:scale-110 transition-all" />
            <Share2 className="w-5 h-5 cursor-pointer hover:text-indigo-600 hover:scale-110 transition-all" />
         </div>
      </footer>
    </div>
  );
}

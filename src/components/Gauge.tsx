import React from 'react';
import { ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';
import { motion } from 'motion/react';
import { cn } from '../lib/utils';

interface GaugeProps {
  score: number;
  level: 'LOW' | 'MEDIUM' | 'HIGH';
}

export const Gauge: React.FC<GaugeProps> = ({ score, level }) => {
  const data = [
    { value: score },
    { value: 100 - score },
  ];

  const getColor = () => {
    switch (level) {
      case 'HIGH': return '#ef4444';
      case 'MEDIUM': return '#f59e0b';
      case 'LOW': return '#10b981';
      default: return '#94a3b8';
    }
  };

  return (
    <div className="relative w-full h-[360px] flex items-center justify-center overflow-hidden">
      {/* Decorative semi-circle boundary */}
      <div className="absolute bottom-0 w-[400px] h-[400px] rounded-full border border-indigo-50/30 pointer-events-none" />
      
      <ResponsiveContainer width="100%" height="100%">
        <PieChart margin={{ top: 0, right: 0, bottom: 0, left: 0 }}>
          <Pie
            data={[{ value: 100 }]}
            cx="50%"
            cy="100%"
            startAngle={180}
            endAngle={0}
            innerRadius={150}
            outerRadius={175}
            paddingAngle={0}
            dataKey="value"
            stroke="none"
          >
            <Cell fill="#f8fafc" />
          </Pie>
          
          <Pie
            data={data}
            cx="50%"
            cy="100%"
            startAngle={180}
            endAngle={0}
            innerRadius={150}
            outerRadius={175}
            paddingAngle={0}
            dataKey="value"
            stroke="none"
            animationDuration={2000}
            animationBegin={200}
          >
            <Cell fill={getColor()} className="transition-all duration-1000" />
            <Cell fill="transparent" />
          </Pie>
        </PieChart>
      </ResponsiveContainer>

      {/* Centered Content Section */}
      <div className="absolute bottom-8 flex flex-col items-center justify-center text-center">
        <motion.div 
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8, delay: 0.4, ease: [0.23, 1, 0.32, 1] }}
          className="flex flex-col items-center"
        >
          <div className="flex items-baseline gap-1 -mb-4">
            <span className="text-[140px] font-black tracking-[-0.06em] tabular-nums text-indigo-950 leading-[0.7]">
              {score}
            </span>
            <span className="text-indigo-300 text-4xl font-black mb-4">%</span>
          </div>
          
          <div className="mt-4 px-8 py-3 rounded-2xl bg-white/80 backdrop-blur-xl border border-indigo-50 shadow-premium flex items-center gap-4">
            <motion.div 
              animate={{ opacity: [0.4, 1, 0.4] }}
              transition={{ repeat: Infinity, duration: 2 }}
              className={cn(
                "w-3 h-3 rounded-full shadow-[0_0_12px_rgba(79,70,229,0.4)]",
                level === 'HIGH' ? "bg-rose-500 shadow-rose-500/50" : level === 'MEDIUM' ? "bg-amber-500 shadow-amber-500/50" : "bg-emerald-500 shadow-emerald-500/50"
              )} 
            />
            <span className={cn(
              "text-[12px] font-black uppercase tracking-[0.4em]",
              level === 'HIGH' ? "text-rose-600" : level === 'MEDIUM' ? "text-amber-600" : "text-emerald-600"
            )}>
              {level}_STATUS
            </span>
          </div>
        </motion.div>
      </div>
    </div>
  );
};

// Helper inside component since we need cn
// removed duplicate import at bottom

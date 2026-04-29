import React from 'react';
import { Lock, Globe, AlertTriangle, Key } from 'lucide-react';
import { PREVENTION_TIPS } from '../constants';

const icons: Record<string, any> = {
  Lock: Lock,
  Globe: Globe,
  AlertTriangle: AlertTriangle,
  Key: Key
};

export const PreventionTips: React.FC = () => {
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
      {PREVENTION_TIPS.map((tip, idx) => {
        const Icon = icons[tip.icon];
        return (
          <div key={idx} className="p-10 bg-white border border-indigo-100 rounded-[40px] hover:-translate-y-2 transition-all duration-500 group shadow-lg shadow-indigo-600/5">
            <div className="w-14 h-14 rounded-2xl bg-indigo-50 flex items-center justify-center mb-8 group-hover:scale-110 transition-transform shadow-sm">
              {Icon && <Icon className="w-6 h-6 text-indigo-600" />}
            </div>
            <h3 className="text-sm font-black uppercase tracking-[0.2em] text-indigo-950 mb-4">{tip.title}</h3>
            <p className="text-xs text-indigo-300 leading-relaxed font-bold tracking-tight">{tip.description}</p>
          </div>
        );
      })}
    </div>
  );
};

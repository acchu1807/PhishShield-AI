import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatDate(date: string | Date) {
  return new Date(date).toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function getRiskColor(level: string) {
  switch (level) {
    case 'HIGH': return 'text-red-500';
    case 'MEDIUM': return 'text-amber-500';
    case 'LOW': return 'text-emerald-500';
    default: return 'text-gray-500';
  }
}

export function getRiskBg(level: string) {
  switch (level) {
    case 'HIGH': return 'bg-red-500/10 border-red-500/20';
    case 'MEDIUM': return 'bg-amber-500/10 border-amber-500/20';
    case 'LOW': return 'bg-emerald-500/10 border-emerald-500/20';
    default: return 'bg-gray-500/10 border-gray-500/20';
  }
}

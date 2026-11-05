import React from 'react';
import { AlertTriangle } from 'lucide-react';

interface Props {
  message?: string;
  onRetry?: () => void;
}

export const LoadError: React.FC<Props> = ({
  message = "Couldn't load this view. Check that the backend is running.",
  onRetry,
}) => (
  <div className="rounded-xl border border-amber-500/40 bg-amber-950/30 px-4 py-3 flex flex-wrap items-center gap-3">
    <AlertTriangle className="w-4 h-4 text-amber-300 shrink-0" />
    <p className="text-sm text-amber-100/90 flex-1">{message}</p>
    {onRetry && (
      <button
        type="button"
        onClick={onRetry}
        className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-amber-500/20 hover:bg-amber-500/30 text-amber-200 border border-amber-500/40"
      >
        Retry
      </button>
    )}
  </div>
);

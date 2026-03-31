import type { LiveTrafficEntry } from '../api/dashboard';

interface Props {
  entry: LiveTrafficEntry;
}

const methodClassMap: Record<string, string> = {
  GET: 'badge-method badge-method-get',
  POST: 'badge-method badge-method-post',
};

export function LiveTrafficRow({ entry }: Props) {
  const isMalicious = entry.verdict === 'malicious';
  const methodClass = methodClassMap[entry.method.toUpperCase()] ?? 'badge-method badge-method-get';

  return (
    <div
      className={`flex flex-col gap-1 rounded-lg border px-3 py-2 text-xs ${
        isMalicious ? 'row-malicious' : 'row-benign'
      }`}
    >
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <span className="text-[11px] text-panel/70">
            [{new Date(entry.timestamp).toLocaleTimeString()}]
          </span>
          <span className={methodClass}>{entry.method.toUpperCase()}</span>
          <span className="truncate font-medium text-panel">{entry.path}</span>
        </div>
        <span className="text-[11px] text-panel/70">
          from {entry.ip} – {entry.statusCode}
        </span>
      </div>

      {isMalicious && (
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-[11px] font-semibold text-panel underline decoration-panel/30 underline-offset-2">
            {entry.attackType ?? 'Malicious request detected'}
          </span>
          {entry.ruleId && <span className="badge-rule">Rule: {entry.ruleId}</span>}
          {typeof entry.aiConfidence === 'number' && (
            <span className="text-[11px] text-panel/70">
              AI Confidence:{' '}
              <span className="font-semibold">
                {(entry.aiConfidence * 100).toFixed(1)}
                %
              </span>
            </span>
          )}
        </div>
      )}
    </div>
  );
}


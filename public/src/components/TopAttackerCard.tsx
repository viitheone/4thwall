import type { TopAttacker } from '../api/dashboard';

interface Props {
  attacker: TopAttacker;
  maxAttempts: number;
}

export function TopAttackerCard({ attacker, maxAttempts }: Props) {
  const ratio = maxAttempts > 0 ? attacker.attempts / maxAttempts : 0;

  return (
    <div className="flex flex-col gap-1 rounded-md border border-panel/25 bg-panel/5 px-3 py-2">
      <div className="flex items-baseline justify-between">
        <span className="text-sm text-panel">{attacker.ip}</span>
        <span className="text-xs font-semibold text-panel">
          {attacker.attempts.toLocaleString()} attempts
        </span>
      </div>
      <div className="h-1.5 w-full overflow-hidden rounded-full bg-panel/20">
        <div
          className="h-full rounded-full bg-panel"
          style={{ width: `${Math.max(6, ratio * 100)}%` }}
        />
      </div>
    </div>
  );
}


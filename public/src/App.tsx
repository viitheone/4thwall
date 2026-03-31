import {
  useEffect,
  useCallback,
  useMemo,
  useState,
} from 'react';
import {
  AiModelStatus,
  AttackDistributionPoint,
  AttacksByHourPoint,
  LiveTrafficEntry,
  SummaryStats,
  TopAttacker,
  fetchAiModelStatus,
  fetchAttackDistribution,
  fetchAttacksByHour,
  fetchLiveTraffic,
  fetchSummaryStats,
  fetchTopAttackers,
} from './api/dashboard';
import { LiveTrafficRow } from './components/LiveTrafficRow';
import { TopAttackerCard } from './components/TopAttackerCard';
import {
  Bar,
  BarChart,
  CartesianGrid,
  Legend,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
  Pie,
  PieChart,
  Cell,
} from 'recharts';

const REFRESH_INTERVAL_MS = 1000;
const TRAFFIC_PANEL_HEIGHT = 'h-[30rem]';

function useDashboardData() {
  const [summary, setSummary] = useState<SummaryStats | null>(null);
  const [traffic, setTraffic] = useState<LiveTrafficEntry[]>([]);
  const [distribution, setDistribution] = useState<AttackDistributionPoint[]>([]);
  const [byHour, setByHour] = useState<AttacksByHourPoint[]>([]);
  const [topAttackers, setTopAttackers] = useState<TopAttacker[]>([]);
  const [aiStatus, setAiStatus] = useState<AiModelStatus | null>(null);

  const refreshAll = useCallback(async () => {
    try {
      const [s, d, h, t, a, live] = await Promise.all([
        fetchSummaryStats(),
        fetchAttackDistribution(),
        fetchAttacksByHour(),
        fetchTopAttackers(),
        fetchAiModelStatus(),
        fetchLiveTraffic(),
      ]);
      setSummary(s);
      setDistribution(d);
      setByHour(h);
      setTopAttackers(t);
      setAiStatus(a);
      setTraffic(live);
    } catch {
      // keep previous successful state on transient polling failures
    }
  }, []);

  useEffect(() => {
    void refreshAll();
    const id = setInterval(() => {
      void refreshAll();
    }, REFRESH_INTERVAL_MS);
    return () => clearInterval(id);
  }, [refreshAll]);

  return { summary, traffic, distribution, byHour, topAttackers, aiStatus };
}

const ATTACK_COLORS = [
  '#ef4444',
  '#f97316',
  '#eab308',
  '#22c55e',
  '#06b6d4',
  '#3b82f6',
  '#a855f7',
  '#ec4899',
];

function App() {
  const { summary, traffic, distribution, byHour, topAttackers, aiStatus } = useDashboardData();

  const maxAttempts = useMemo(
    () => topAttackers.reduce((max, a) => Math.max(max, a.attempts), 0),
    [topAttackers],
  );

  return (
    <div className="min-h-screen bg-background px-8 py-6 text-panel">
      <header className="mb-6 flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-panel">4thwall</h1>
          <p className="text-sm text-panel/70">
            Real-time anomaly detection for web traffic
          </p>
        </div>
        <div className="rounded border border-panel/40 bg-panel/10 px-3 py-1 text-xs font-medium text-panel shadow-card backdrop-blur-md">
          <span className="text-[11px] text-panel">LIVE</span>{' '}
          <span className="text-panel/70">
            {new Date().toLocaleTimeString(undefined, { hour12: true })}
          </span>
        </div>
      </header>

      <main className="grid grid-cols-12 gap-4">
        <section className="col-span-12 grid grid-cols-4 gap-4">
          <div className="card-soc px-4 py-3">
            <div className="card-header">
              <span className="text-xs font-medium uppercase tracking-wide text-panel/70">
                Total Requests Today
              </span>
            </div>
            <p className="text-2xl font-semibold text-panel">
              {summary ? summary.totalRequests.toLocaleString() : '--'}
            </p>
          </div>
          <div className="card-soc px-4 py-3">
            <div className="card-header">
              <span className="text-xs font-medium uppercase tracking-wide text-panel/70">
                Benign Requests
              </span>
            </div>
            <p className="text-2xl font-semibold text-panel">
              {summary ? summary.benignRequests.toLocaleString() : '--'}
            </p>
          </div>
          <div className="card-soc px-4 py-3">
            <div className="card-header">
              <span className="text-xs font-medium uppercase tracking-wide text-panel/70">
                Malicious Requests Detected
              </span>
            </div>
            <p className="text-2xl font-semibold text-panel underline decoration-panel/30 underline-offset-4">
              {summary ? summary.maliciousRequests.toLocaleString() : '--'}
            </p>
          </div>
          <div className="card-soc px-4 py-3">
            <div className="card-header">
              <span className="text-xs font-medium uppercase tracking-wide text-panel/70">
                Detection Accuracy
              </span>
            </div>
            <p className="text-2xl font-semibold text-panel">
              {summary ? `${summary.accuracy.toFixed(2)}%` : '--'}
            </p>
          </div>
        </section>

        <section className="col-span-7 row-span-2 card-soc flex flex-col px-4 py-3">
          <div className="card-header">
            <h2 className="text-sm font-semibold text-panel">Live Traffic Monitor</h2>
          </div>
          <div className={`${TRAFFIC_PANEL_HEIGHT} space-y-2 overflow-y-auto pr-1 custom-scrollbar`}>
            {traffic.map((entry) => (
              <LiveTrafficRow key={entry.id} entry={entry} />
            ))}
            {traffic.length === 0 && (
              <p className="text-xs text-panel/70">Waiting for traffic data from backend…</p>
            )}
          </div>
        </section>

        <section className="col-span-5 card-soc flex flex-col px-4 py-3">
          <div className="card-header">
            <h2 className="text-sm font-semibold text-panel">Attack Distribution</h2>
          </div>
          <div className="h-56">
            {distribution.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    dataKey="count"
                    nameKey="type"
                    data={distribution}
                    innerRadius={50}
                    outerRadius={80}
                    paddingAngle={3}
                    labelLine={false}
                    label={({ cx, cy, midAngle, outerRadius, percent }) => {
                      const radius = (outerRadius ?? 80) + 16;
                      const x = (cx ?? 0) + radius * Math.cos((-midAngle * Math.PI) / 180);
                      const y = (cy ?? 0) + radius * Math.sin((-midAngle * Math.PI) / 180);
                      return (
                        <text x={x} y={y} fill="#eae0d5" fontSize={11} textAnchor={x > (cx ?? 0) ? 'start' : 'end'}>
                          {`${((percent ?? 0) * 100).toFixed(0)}%`}
                        </text>
                      );
                    }}
                  >
                    {distribution.map((_, index) => (
                      <Cell key={index} fill={ATTACK_COLORS[index % ATTACK_COLORS.length]} />
                    ))}
                  </Pie>
                  <Legend
                    formatter={(value) => <span style={{ color: '#eae0d5' }}>{value}</span>}
                    wrapperStyle={{ fontSize: 11 }}
                  />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#0a0908',
                      borderColor: '#eae0d5',
                      color: '#eae0d5',
                      fontSize: 11,
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <p className="text-xs text-panel/70">
                No attack distribution data available yet.
              </p>
            )}
          </div>
        </section>

        <section className="col-span-5 card-soc flex flex-col px-4 py-3">
          <div className="card-header">
            <h2 className="text-sm font-semibold text-panel">Top Attacker IPs</h2>
          </div>
          <div className="space-y-2">
            {topAttackers.slice(0, 5).map((attacker) => (
              <TopAttackerCard key={attacker.ip} attacker={attacker} maxAttempts={maxAttempts} />
            ))}
            {topAttackers.length === 0 && (
              <p className="text-xs text-panel/70">
                No malicious traffic recorded yet. Top attacker list will auto-populate from
                live logs.
              </p>
            )}
          </div>
        </section>

        <section className="col-span-7 card-soc flex flex-col px-4 py-3">
          <div className="card-header">
            <h2 className="text-sm font-semibold text-panel">AI Model Status</h2>
          </div>
          {aiStatus ? (
            <div className="grid grid-cols-3 gap-4 text-xs text-panel">
              <div className="space-y-1">
                <p className="font-semibold text-panel">Model Information</p>
                <p>Architecture: {aiStatus.architecture}</p>
                <p>Version: {aiStatus.version}</p>
                <p>Parameters: {aiStatus.parameters}</p>
              </div>
              <div className="space-y-1">
                <p className="font-semibold text-panel">Training Status</p>
                <p>Progress: {aiStatus.trainingProgress.toFixed(1)}%</p>
                <div className="h-1.5 w-full overflow-hidden rounded-full bg-panel/20">
                  <div
                    className="h-full rounded-full bg-panel"
                    style={{ width: `${aiStatus.trainingProgress}%` }}
                  />
                </div>
                <p>Last updated: {new Date(aiStatus.lastUpdated).toLocaleString()}</p>
              </div>
              <div className="space-y-1">
                <p className="font-semibold text-panel">Performance</p>
                <p>Accuracy: {aiStatus.accuracy.toFixed(2)}%</p>
                <p>Precision: {aiStatus.precision.toFixed(2)}%</p>
                <p>Recall: {aiStatus.recall.toFixed(2)}%</p>
                <p>F1: {aiStatus.f1.toFixed(2)}%</p>
              </div>
            </div>
          ) : (
            <p className="text-xs text-panel/70">
              Waiting for AI model status from backend…
            </p>
          )}
        </section>

        <section className="col-span-5 card-soc flex flex-col px-4 py-3">
          <div className="card-header">
            <h2 className="text-sm font-semibold text-panel">Attacks by Hour</h2>
          </div>
          <div className="h-48">
            {byHour.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={byHour}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(234,224,213,0.25)" />
                  <XAxis dataKey="hour" tick={{ fontSize: 10, fill: '#eae0d5' }} />
                  <YAxis tick={{ fontSize: 10, fill: '#eae0d5' }} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#0a0908',
                      borderColor: '#eae0d5',
                      color: '#eae0d5',
                      fontSize: 11,
                    }}
                  />
                  <Legend wrapperStyle={{ fontSize: 11 }} />
                  <Bar dataKey="count" name="Malicious attempts">
                    {byHour.map((_, index) => (
                      <Cell key={`hour-cell-${index}`} fill={ATTACK_COLORS[index % ATTACK_COLORS.length]} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <p className="text-xs text-panel/70">No hourly attack data available yet.</p>
            )}
          </div>
        </section>
      </main>
    </div>
  );
}

export default App;


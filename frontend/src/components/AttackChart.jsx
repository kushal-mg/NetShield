import React from "react";
import {
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Tooltip,
  Legend,
  BarChart,
  Bar,
  XAxis,
  YAxis,
} from "recharts";

const ATTACK_COLORS = {
  "DDoS": "#ff0055",
  "Port Scan": "#00d4ff",
  "Brute Force": "#ffaa00",
  "Botnet": "#b900ff"
};

const SEVERITY_COLORS = {
  "Critical": "#ef4444",
  "High": "#f97316",
  "Medium": "#eab308",
  "Low": "#10b981"
};

export default function AttackChart({ stats }) {
  // 1. Process Attack Data
  const attackBreakdown = stats?.attack_breakdown || {};
  const attackData = Object.entries(attackBreakdown)
    .map(([name, value]) => ({ name, value }))
    .filter((item) => item.value > 0);

  // 2. Process Severity Data
  const severityBreakdown = stats?.severity_breakdown || {};
  const severityData = Object.entries(severityBreakdown).map(([name, value]) => ({
    name,
    value,
  }));

  const hasData = stats?.total_alerts > 0;

  if (!hasData) {
    return (
      <div className="cyber-card chart-card" style={{ gridColumn: "span 4", alignItems: "center", justifyContent: "center", minHeight: "280px" }}>
        <p className="subtitle-main" style={{ fontSize: "1rem" }}>NO THREATS DETECTED</p>
        <p className="stat-label" style={{ marginTop: "0.5rem" }}>Launch the simulator to stream live network flows and verify classification telemetry.</p>
      </div>
    );
  }

  return (
    <div className="main-view-layout">
      {/* Chart 1: Threat Distribution (Doughnut) */}
      <div className="cyber-card chart-card">
        <h2 className="chart-title">THREAT TYPE DISTRIBUTION</h2>
        <div style={{ width: "100%", height: "260px" }}>
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={attackData}
                cx="50%"
                cy="50%"
                innerRadius={60}
                outerRadius={85}
                paddingAngle={4}
                dataKey="value"
              >
                {attackData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={ATTACK_COLORS[entry.name] || "#8884d8"} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{
                  background: "#0d1117",
                  border: "1px solid rgba(255,255,255,0.1)",
                  borderRadius: "6px",
                  color: "#f8fafc",
                }}
              />
              <Legend
                verticalAlign="bottom"
                height={36}
                iconType="circle"
                formatter={(value) => <span style={{ color: "#94a3b8", fontSize: "12px", fontFamily: "monospace" }}>{value}</span>}
              />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Chart 2: Threat Severity Breakdown (Bar) */}
      <div className="cyber-card chart-card">
        <h2 className="chart-title">SEVERITY ANALYSIS</h2>
        <div style={{ width: "100%", height: "260px" }}>
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={severityData} margin={{ top: 10, right: 10, left: -25, bottom: 0 }}>
              <XAxis
                dataKey="name"
                stroke="#94a3b8"
                fontSize={10}
                tickLine={false}
                fontFamily="monospace"
              />
              <YAxis
                stroke="#94a3b8"
                fontSize={10}
                tickLine={false}
                fontFamily="monospace"
              />
              <Tooltip
                cursor={{ fill: "rgba(255, 255, 255, 0.03)" }}
                contentStyle={{
                  background: "#0d1117",
                  border: "1px solid rgba(255,255,255,0.1)",
                  borderRadius: "6px",
                  color: "#f8fafc",
                }}
              />
              <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                {severityData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={SEVERITY_COLORS[entry.name] || "#8884d8"} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
}

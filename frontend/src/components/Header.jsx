import React from "react";
import { Shield, Play, Square, Activity } from "lucide-react";

export default function Header({ simulatorRunning, onStartSim, onStopSim }) {
  return (
    <header className="cyber-card header">
      <div className="logo-section">
        <Shield className="logo-icon" size={36} />
        <div>
          <h1 className="title-main">NetShield</h1>
          <p className="subtitle-main">AI-DRIVEN NETWORK INTRUSION DETECTION SYSTEM</p>
        </div>
      </div>
      
      <div className="controls-section">
        <div className="sim-badge">
          <Activity size={16} className={simulatorRunning ? "logo-icon" : ""} />
          <span>Status: </span>
          <div className={`sim-dot ${simulatorRunning ? "active" : ""}`} />
          <span style={{ color: simulatorRunning ? "#00e676" : "#94a3b8" }}>
            {simulatorRunning ? "Active Scanning" : "Idle"}
          </span>
        </div>

        {simulatorRunning ? (
          <button className="btn-cyber stop" onClick={onStopSim}>
            <Square size={16} fill="white" />
            Stop Simulator
          </button>
        ) : (
          <button className="btn-cyber" onClick={onStartSim}>
            <Play size={16} fill="black" />
            Start Simulator
          </button>
        )}
      </div>
    </header>
  );
}

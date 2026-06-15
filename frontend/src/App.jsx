import React, { useState, useEffect } from "react";
import axios from "axios";
import { AlertCircle, RefreshCw } from "lucide-react";
import Header from "./components/Header";
import StatsCards from "./components/StatsCards";
import AttackChart from "./components/AttackChart";
import AlertFeed from "./components/AlertFeed";

const API_BASE = "http://localhost:8000/api";

export default function App() {
  const [alerts, setAlerts] = useState([]);
  const [stats, setStats] = useState(null);
  const [simulatorRunning, setSimulatorRunning] = useState(false);
  const [backendError, setBackendError] = useState(false);
  const [isRefreshing, setIsRefreshing] = useState(false);

  const fetchData = async () => {
    try {
      // Parallel API calls
      const [alertsRes, statsRes] = await Promise.all([
        axios.get(`${API_BASE}/alerts`),
        axios.get(`${API_BASE}/stats`)
      ]);
      
      setAlerts(alertsRes.data);
      setStats(statsRes.data);
      setSimulatorRunning(statsRes.data.simulator_running);
      setBackendError(false);
    } catch (err) {
      console.error("Error communicating with API backend:", err);
      setBackendError(true);
    }
  };

  // Poll server data at regular intervals
  useEffect(() => {
    // Initial fetch
    fetchData();

    // 2-second interval for real-time dashboard refresh
    const interval = setInterval(() => {
      fetchData();
    }, 2000);

    return () => clearInterval(interval);
  }, []);

  const handleStartSim = async () => {
    try {
      setIsRefreshing(true);
      const res = await axios.post(`${API_BASE}/simulate/start`);
      if (res.data.running) {
        setSimulatorRunning(true);
        fetchData();
      }
    } catch (err) {
      console.error("Failed to start simulator:", err);
      alert("Error starting network simulation: make sure FastAPI server is running.");
    } finally {
      setIsRefreshing(false);
    }
  };

  const handleStopSim = async () => {
    try {
      setIsRefreshing(true);
      const res = await axios.post(`${API_BASE}/simulate/stop`);
      if (!res.data.running) {
        setSimulatorRunning(false);
        fetchData();
      }
    } catch (err) {
      console.error("Failed to stop simulator:", err);
      alert("Error stopping network simulation.");
    } finally {
      setIsRefreshing(false);
    }
  };

  return (
    <div className="app-container">
      {/* Backend Status Warning */}
      {backendError && (
        <div 
          className="cyber-card" 
          style={{ 
            display: "flex", 
            alignItems: "center", 
            gap: "0.75rem", 
            borderColor: "#ef4444", 
            background: "rgba(239, 68, 68, 0.05)",
            color: "#ef4444",
            padding: "0.75rem 1rem",
            fontSize: "0.9rem",
            fontFamily: "monospace"
          }}
        >
          <AlertCircle size={20} />
          <span>OFFLINE DETECTED: Unable to establish database connection with FastAPI backend on http://localhost:8000. Start the backend service first.</span>
          <button 
            style={{ 
              background: "transparent", 
              border: "none", 
              color: "#ef4444", 
              cursor: "pointer", 
              marginLeft: "auto",
              display: "flex",
              alignItems: "center",
              gap: "0.3rem"
            }}
            onClick={fetchData}
          >
            <RefreshCw size={14} className={isRefreshing ? "logo-icon" : ""} />
            Retry
          </button>
        </div>
      )}

      {/* Title Header */}
      <Header 
        simulatorRunning={simulatorRunning} 
        onStartSim={handleStartSim} 
        onStopSim={handleStopSim} 
      />

      {/* Dashboard KPI Stats */}
      <StatsCards stats={stats} />

      {/* Visual Analytics */}
      <AttackChart stats={stats} />

      {/* Live Logs Table */}
      <AlertFeed alerts={alerts} />
    </div>
  );
}

import React, { useState } from "react";
import { ChevronDown, ChevronUp, Cpu, Server, Network } from "lucide-react";

export default function AlertFeed({ alerts }) {
  const [expandedId, setExpandedId] = useState(null);

  const toggleRow = (id) => {
    if (expandedId === id) {
      setExpandedId(null);
    } else {
      setExpandedId(id);
    }
  };

  const getSeverityClass = (severity) => {
    switch (severity?.toLowerCase()) {
      case "critical":
        return "badge critical";
      case "high":
        return "badge high";
      case "medium":
        return "badge medium";
      case "low":
        return "badge low";
      default:
        return "badge low";
    }
  };

  const formatTimestamp = (isoStr) => {
    try {
      const d = new Date(isoStr);
      return d.toLocaleTimeString() + " " + d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
    } catch {
      return isoStr;
    }
  };

  const renderFeatures = (featuresJson) => {
    try {
      const features = typeof featuresJson === "string" ? JSON.parse(featuresJson) : featuresJson;
      // Filter out 'Label' if present in features
      const filtered = Object.entries(features || {}).filter(([k]) => k !== "Label");
      
      return (
        <div className="feature-grid">
          {filtered.map(([key, val]) => (
            <div className="feature-item" key={key}>
              <span className="feature-label">{key}</span>
              <span className="feature-value">
                {typeof val === "number" ? (val % 1 !== 0 ? val.toFixed(4) : val) : String(val)}
              </span>
            </div>
          ))}
        </div>
      );
    } catch (e) {
      return <p style={{ color: "red" }}>Error parsing network features.</p>;
    }
  };

  const renderMarkdown = (mdText) => {
    if (!mdText) {
      return <p className="subtitle-main">AI analyst summary is not available for this alert.</p>;
    }

    // A simple custom markdown parser to convert standard headers, bold, bullets, and pre-blocks to HTML elements safely
    const lines = mdText.split("\n");
    let inPre = false;
    let preCode = [];
    
    return lines.map((line, idx) => {
      // Handle code block sections
      if (line.trim().startsWith("```")) {
        if (inPre) {
          inPre = false;
          const codeContent = preCode.join("\n");
          preCode = [];
          return (
            <pre key={idx}>
              <code>{codeContent}</code>
            </pre>
          );
        } else {
          inPre = true;
          return null;
        }
      }

      if (inPre) {
        preCode.push(line);
        return null;
      }

      // Headers
      if (line.startsWith("#### ")) {
        return <h4 key={idx}>{line.substring(5)}</h4>;
      }
      if (line.startsWith("### ")) {
        return <h3 key={idx}>{line.substring(4)}</h3>;
      }
      if (line.startsWith("## ")) {
        return <h2 key={idx}>{line.substring(3)}</h2>;
      }

      // Unordered lists
      if (line.trim().startsWith("* ") || line.trim().startsWith("- ")) {
        const itemText = line.trim().substring(2);
        // Basic replacement of bold tags inside lists
        const boldParsed = itemText.split("**").map((text, i) => i % 2 === 1 ? <strong key={i}>{text}</strong> : text);
        return <li key={idx} style={{ marginLeft: "1.25rem", marginBottom: "0.2rem" }}>{boldParsed}</li>;
      }

      if (line.trim() === "") {
        return <div key={idx} style={{ height: "0.5rem" }} />;
      }

      // Paragraph lines
      const boldParsed = line.split("**").map((text, i) => i % 2 === 1 ? <strong key={i}>{text}</strong> : text);
      return <p key={idx} style={{ marginBottom: "0.5rem" }}>{boldParsed}</p>;
    });
  };

  return (
    <div className="cyber-card alert-feed-card">
      <h2 className="chart-title">LIVE INTRUSION ALERTS FEED</h2>
      
      {alerts.length === 0 ? (
        <div style={{ padding: "2rem", textAlign: "center", color: "#94a3b8" }}>
          <p className="subtitle-main">FEED SILENT</p>
          <p style={{ fontSize: "0.85rem", marginTop: "0.5rem" }}>No active network threats classified. Enable the traffic simulator to run telemetry scans.</p>
        </div>
      ) : (
        <div className="table-wrapper">
          <table className="cyber-table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Threat classified</th>
                <th>Source Address</th>
                <th>Destination Address</th>
                <th>Confidence</th>
                <th>Severity</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {alerts.map((alert) => {
                const isExpanded = expandedId === alert.id;
                return (
                  <React.Fragment key={alert.id}>
                    <tr 
                      className={isExpanded ? "selected" : ""} 
                      onClick={() => toggleRow(alert.id)}
                    >
                      <td>{formatTimestamp(alert.timestamp)}</td>
                      <td style={{ color: "#fff", fontWeight: "600" }}>{alert.attack_type}</td>
                      <td>{alert.src_ip}:{alert.src_port}</td>
                      <td>{alert.dst_ip}:{alert.dst_port}</td>
                      <td>{(alert.confidence * 100).toFixed(2)}%</td>
                      <td>
                        <span className={getSeverityClass(alert.severity)}>
                          {alert.severity}
                        </span>
                      </td>
                      <td style={{ textAlign: "right" }}>
                        {isExpanded ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
                      </td>
                    </tr>
                    
                    {isExpanded && (
                      <tr>
                        <td colSpan="7" style={{ padding: 0, cursor: "default", background: "transparent" }}>
                          <div className="details-container">
                            {/* Raw Features column */}
                            <div className="details-panel">
                              <h3 className="details-title">
                                <Cpu size={16} />
                                FLOW SEGMENT PARAMETERS (RAW FEATURES)
                              </h3>
                              {renderFeatures(alert.features)}
                            </div>
                            
                            {/* AI Threat Report column */}
                            <div className="details-panel">
                              <h3 className="details-title">
                                <Server size={16} />
                                AI ANALYST INCIDENT REPORT
                              </h3>
                              <div className="ai-markdown-view">
                                {renderMarkdown(alert.ai_summary)}
                              </div>
                            </div>
                          </div>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

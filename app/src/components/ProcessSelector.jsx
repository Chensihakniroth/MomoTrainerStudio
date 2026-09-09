import React, { useState, useEffect } from 'react';
import './ProcessSelector.css';

export default function ProcessSelector({ onSelect }) {
  const [processes, setProcesses] = useState([]);
  const [selectedPid, setSelectedPid] = useState(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    loadProcesses();
  }, []);

  const loadProcesses = async () => {
    setLoading(true);
    try {
      const result = await window.api.listProcesses();
      if (result.processes) {
        setProcesses(result.processes.sort((a, b) => a.name.localeCompare(b.name)));
      }
    } catch (err) {
      console.error('Error loading processes:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleAttach = async (pid) => {
    try {
      const result = await window.api.attachProcess(pid);
      if (!result.error) {
        setSelectedPid(pid);
        onSelect({ pid, name: processes.find(p => p.pid === pid)?.name });
      }
    } catch (err) {
      console.error('Error attaching:', err);
    }
  };

  return (
    <div className="process-selector">
      <div className="selector-header">
        <label>Process:</label>
        <button 
          className="refresh-btn"
          onClick={loadProcesses}
          disabled={loading}
        >
          {loading ? '⟳' : '↻'} Refresh
        </button>
      </div>
      
      <select 
        className="process-select"
        value={selectedPid || ''}
        onChange={(e) => {
          const pid = parseInt(e.target.value);
          if (pid) handleAttach(pid);
        }}
      >
        <option value="">Select process...</option>
        {processes.map(proc => (
          <option key={proc.pid} value={proc.pid}>
            {proc.name} ({proc.pid})
          </option>
        ))}
      </select>

      {selectedPid && (
        <div className="attached-status">
          ✓ Attached to PID {selectedPid}
        </div>
      )}
    </div>
  );
}

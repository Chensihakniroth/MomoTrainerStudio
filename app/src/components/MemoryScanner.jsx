import React, { useState } from 'react';
import './MemoryScanner.css';

export default function MemoryScanner({ process, onScanComplete }) {
  const [scanValue, setScanValue] = useState('');
  const [valueType, setValueType] = useState('int32');
  const [scanMode, setScanMode] = useState('exact');
  const [scanning, setScanning] = useState(false);
  const [resultCount, setResultCount] = useState(0);

  const handleScan = async () => {
    if (!process || !scanValue) {
      alert('Select a process and enter a value');
      return;
    }

    setScanning(true);
    try {
      const result = await window.api.startScan({
        value: scanValue,
        value_type: valueType,
        scan_mode: scanMode,
      });

      if (result.error) {
        alert(`Scan error: ${result.error}`);
      } else {
        setResultCount(result.count);
        onScanComplete(result.addresses || []);
      }
    } catch (err) {
      alert(`Scan failed: ${err.message}`);
    } finally {
      setScanning(false);
    }
  };

  return (
    <div className="memory-scanner">
      <h2>Memory Scanner</h2>
      
      <div className="scanner-form">
        <div className="form-group">
          <label>Search Value:</label>
          <input
            type="text"
            value={scanValue}
            onChange={(e) => setScanValue(e.target.value)}
            placeholder="Enter value to search"
            disabled={scanning}
          />
        </div>

        <div className="form-row">
          <div className="form-group">
            <label>Value Type:</label>
            <select
              value={valueType}
              onChange={(e) => setValueType(e.target.value)}
              disabled={scanning}
            >
              <option value="int32">4 Bytes (Int32)</option>
              <option value="float">Float</option>
              <option value="double">Double</option>
              <option value="uint8">Byte</option>
              <option value="int16">2 Bytes</option>
              <option value="int64">8 Bytes</option>
              <option value="uint32">UInt32</option>
              <option value="uint64">UInt64</option>
              <option value="string">String</option>
            </select>
          </div>

          <div className="form-group">
            <label>Scan Mode:</label>
            <select
              value={scanMode}
              onChange={(e) => setScanMode(e.target.value)}
              disabled={scanning}
            >
              <option value="exact">Exact Value</option>
              <option value="increased">Increased</option>
              <option value="decreased">Decreased</option>
              <option value="changed">Changed</option>
              <option value="unchanged">Unchanged</option>
            </select>
          </div>
        </div>

        <button
          className="scan-btn"
          onClick={handleScan}
          disabled={scanning || !process}
        >
          {scanning ? '⟳ Scanning...' : '▶ Scan'}
        </button>
      </div>

      {resultCount > 0 && (
        <div className="scan-result">
          Found <span className="result-count">{resultCount}</span> address(es)
        </div>
      )}
    </div>
  );
}

import React, { useState, useEffect } from 'react';
import './App.css';
import ProcessSelector from './components/ProcessSelector';
import MemoryScanner from './components/MemoryScanner';
import AddressTable from './components/AddressTable';
import HexViewer from './components/HexViewer';

export default function App() {
  const [selectedProcess, setSelectedProcess] = useState(null);
  const [foundAddresses, setFoundAddresses] = useState([]);
  const [selectedAddress, setSelectedAddress] = useState(null);
  const [hexData, setHexData] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleScanComplete = (addresses) => {
    setFoundAddresses(addresses);
  };

  const handleAddressSelect = async (address) => {
    setSelectedAddress(address);
    setLoading(true);
    try {
      const result = await window.api.readMemory(address, 256);
      if (result.data) {
        setHexData(result.data);
      }
    } catch (err) {
      console.error('Error reading memory:', err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="app">
      <header className="app-header">
        <div className="header-content">
          <h1>MomoTrainer Studio</h1>
          <ProcessSelector onSelect={setSelectedProcess} />
        </div>
      </header>

      <main className="app-main">
        <div className="left-panel">
          <MemoryScanner 
            process={selectedProcess}
            onScanComplete={handleScanComplete}
          />
          <AddressTable
            addresses={foundAddresses}
            onSelectAddress={handleAddressSelect}
            selectedAddress={selectedAddress}
          />
        </div>

        <div className="right-panel">
          {selectedAddress ? (
            <HexViewer
              address={selectedAddress}
              data={hexData}
              loading={loading}
            />
          ) : (
            <div className="hex-placeholder">
              <p>Select an address to view memory</p>
            </div>
          )}
        </div>
      </main>
    </div>
  );
}

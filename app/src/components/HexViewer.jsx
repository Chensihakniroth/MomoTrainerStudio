import React, { useState, useEffect } from 'react';
import './HexViewer.css';

export default function HexViewer({ address, data, loading }) {
  const [hexLines, setHexLines] = useState([]);

  useEffect(() => {
    if (data) {
      // Parse hex string into 16-byte lines
      const lines = [];
      for (let i = 0; i < data.length; i += 32) { // 32 chars = 16 bytes
        const hexChunk = data.substr(i, 32);
        const asciiChunk = hexChunk
          .match(/.{1,2}/g)
          .map(b => String.fromCharCode(parseInt(b, 16)))
          .map(c => /[\x20-\x7E]/.test(c) ? c : '.')
          .join('');
        
        lines.push({
          offset: address + (i / 2),
          hex: hexChunk.match(/.{1,2}/g).join(' '),
          ascii: asciiChunk,
        });
      }
      setHexLines(lines);
    }
  }, [data, address]);

  return (
    <div className="hex-viewer">
      <h2>Hex Viewer</h2>
      
      <div className="hex-header">
        <span className="hex-address">Address: 0x{address?.toString(16).toUpperCase()}</span>
      </div>

      {loading ? (
        <div className="hex-loading">
          <p>⟳ Loading memory...</p>
        </div>
      ) : (
        <div className="hex-content">
          <table className="hex-table">
            <tbody>
              {hexLines.map((line, idx) => (
                <tr key={idx} className="hex-line">
                  <td className="hex-offset">0x{line.offset.toString(16).toUpperCase().padStart(8, '0')}</td>
                  <td className="hex-bytes">{line.hex}</td>
                  <td className="hex-ascii">{line.ascii}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

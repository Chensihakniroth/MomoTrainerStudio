import React from 'react';
import './AddressTable.css';

export default function AddressTable({ addresses, onSelectAddress, selectedAddress }) {
  return (
    <div className="address-table">
      <h2>Found Addresses ({addresses.length})</h2>
      
      <div className="table-container">
        <table>
          <thead>
            <tr>
              <th>Address</th>
              <th>Value</th>
              <th>Type</th>
            </tr>
          </thead>
          <tbody>
            {addresses.length === 0 ? (
              <tr className="empty-row">
                <td colSpan="3">No addresses found</td>
              </tr>
            ) : (
              addresses.slice(0, 50).map((addr, idx) => (
                <tr
                  key={idx}
                  className={`address-row ${selectedAddress === addr ? 'selected' : ''}`}
                  onClick={() => onSelectAddress(addr)}
                >
                  <td className="address-cell">0x{addr.toString(16).toUpperCase().padStart(8, '0')}</td>
                  <td className="value-cell">-</td>
                  <td className="type-cell">-</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

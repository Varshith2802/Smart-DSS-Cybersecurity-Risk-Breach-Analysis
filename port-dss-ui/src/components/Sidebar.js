import React from 'react';
import { Link } from 'react-router-dom';
import { Nav } from 'react-bootstrap';

export default function Sidebar() {
  return (
    <div className="bg-light p-3" style={{ minHeight: '100vh', width: '220px' }}>
      <h4>📊 Port DSS</h4>
      <Nav defaultActiveKey="/" className="flex-column mt-4">
        <Nav.Link as={Link} to="/">Dashboard</Nav.Link>
        <Nav.Link as={Link} to="/vendors">Vendors</Nav.Link>
        <Nav.Link as={Link} to="/ais">AIS Monitor</Nav.Link>
        <Nav.Link as={Link} to="/logs">Audit Logs</Nav.Link>
      </Nav>
    </div>
  );
}

import React, { useState, useEffect } from 'react';
import { Form, Button, Card, Table, Row, Col } from 'react-bootstrap';
import API from '../api/axiosConfig'; // Make sure this path matches your setup

export default function Vendors() {
  const [vendors, setVendors] = useState([]);
  const [filter, setFilter] = useState('All');
  const [formData, setFormData] = useState({
    name: '',
    software_assets: '',
    cloud_assets: '',
    industrial_assets: '',
    ais_data: false,
  });

  // Load vendors from backend
  useEffect(() => {
    API.get('/vendors')
      .then(res => setVendors(res.data))
      .catch(err => console.error('Error fetching vendors:', err));
  }, []);

  // Submit new vendor
  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      const res = await API.post('/vendors', formData);
      setVendors(prev => [...prev, res.data]);
      setFormData({ name: '', software_assets: '', cloud_assets: '', industrial_assets: '', ais_data: false });
    } catch (err) {
      console.error('Error adding vendor:', err.response?.data || err.message);
    }
  };

  const filteredVendors = filter === 'All'
    ? vendors
    : vendors.filter(v => v.risk_level === filter);

  return (
    <div>
      <h2 className="mb-4">🏢 Vendor Management</h2>

      {/* Filter and Export */}
      <Row className="mb-3">
        <Col md={3}>
          <Form.Select value={filter} onChange={(e) => setFilter(e.target.value)}>
            <option value="All">All Risk Levels</option>
            <option value="Low">Low</option>
            <option value="Medium">Medium</option>
            <option value="High">High</option>
          </Form.Select>
        </Col>
        <Col md={{ span: 2, offset: 7 }}>
          <Button variant="success" className="w-100">Export as CSV</Button>
        </Col>
      </Row>

      {/* Add Vendor Form */}
      <Card className="mb-4 shadow-sm">
        <Card.Body>
          <Card.Title>Add New Vendor</Card.Title>
          <Form onSubmit={handleSubmit}>
            <Row className="mb-2">
              <Col md={6}>
                <Form.Group>
                  <Form.Label>Vendor Name</Form.Label>
                  <Form.Control
                    type="text"
                    required
                    value={formData.name}
                    onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                  />
                </Form.Group>
              </Col>
              <Col md={6}>
                <Form.Group>
                  <Form.Label>Software Assets</Form.Label>
                  <Form.Control
                    type="text"
                    value={formData.software_assets}
                    onChange={(e) => setFormData({ ...formData, software_assets: e.target.value })}
                  />
                </Form.Group>
              </Col>
            </Row>

            <Row className="mb-2">
              <Col md={6}>
                <Form.Group>
                  <Form.Label>Cloud Assets</Form.Label>
                  <Form.Control
                    type="text"
                    value={formData.cloud_assets}
                    onChange={(e) => setFormData({ ...formData, cloud_assets: e.target.value })}
                  />
                </Form.Group>
              </Col>
              <Col md={6}>
                <Form.Group>
                  <Form.Label>Industrial Assets</Form.Label>
                  <Form.Control
                    type="text"
                    value={formData.industrial_assets}
                    onChange={(e) => setFormData({ ...formData, industrial_assets: e.target.value })}
                  />
                </Form.Group>
              </Col>
            </Row>

            <Row>
              <Col md={4}>
                <Form.Group>
                  <Form.Check
                    type="checkbox"
                    label="AIS Data Available?"
                    checked={formData.ais_data}
                    onChange={(e) => setFormData({ ...formData, ais_data: e.target.checked })}
                  />
                </Form.Group>
              </Col>
              <Col md={8} className="d-flex align-items-end">
                <Button type="submit" variant="primary" className="w-100">
                  Submit Vendor
                </Button>
              </Col>
            </Row>
          </Form>
        </Card.Body>
      </Card>

      {/* Vendor Table */}
      <Card className="shadow-sm">
        <Card.Body>
          <Card.Title>All Vendors</Card.Title>
          <Table striped bordered hover responsive className="mt-3">
            <thead>
              <tr>
                <th>Name</th>
                <th>Software</th>
                <th>Cloud</th>
                <th>Industrial</th>
                <th>AIS</th>
                <th>Risk</th>
              </tr>
            </thead>
            <tbody>
              {filteredVendors.map((vendor, idx) => (
                <tr key={idx}>
                  <td>{vendor.name}</td>
                  <td>{vendor.software_assets}</td>
                  <td>{vendor.cloud_assets}</td>
                  <td>{vendor.industrial_assets}</td>
                  <td>{vendor.ais_data ? 'Yes' : 'No'}</td>
                  <td>{vendor.risk_level}</td>
                </tr>
              ))}
            </tbody>
          </Table>
        </Card.Body>
      </Card>
    </div>
  );
}

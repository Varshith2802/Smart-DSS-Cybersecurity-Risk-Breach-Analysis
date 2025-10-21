import React from 'react';
import { Card, Row, Col } from 'react-bootstrap';
import { Bar, Pie } from 'react-chartjs-2';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  BarElement,
  ArcElement,
  Title,
  Tooltip,
  Legend
} from 'chart.js';

// Register Chart.js elements
ChartJS.register(
  CategoryScale,
  LinearScale,
  BarElement,
  ArcElement,
  Title,
  Tooltip,
  Legend
);

// Bar Chart Data (Top 5 Risky Vendors)
const vendorChartData = {
  labels: ['Vendor A', 'Vendor B', 'Vendor C', 'Vendor D', 'Vendor E'],
  datasets: [
    {
      label: 'Risk Score',
      data: [9.5, 8.2, 7.8, 6.5, 6.1],
      backgroundColor: 'rgba(255, 99, 132, 0.6)',
    },
  ],
};

const vendorChartOptions = {
  responsive: true,
  plugins: {
    legend: { position: 'top' },
    title: { display: true, text: 'Top 5 Risky Vendors' },
  },
};

// Pie Chart Data (Risk Level Distribution)
const pieData = {
  labels: ['Low Risk', 'Medium Risk', 'High Risk'],
  datasets: [
    {
      label: 'Risk Level Distribution',
      data: [40, 35, 25],
      backgroundColor: [
        'rgba(75, 192, 192, 0.6)',
        'rgba(255, 205, 86, 0.6)',
        'rgba(255, 99, 132, 0.6)'
      ],
      borderColor: [
        'rgba(75, 192, 192, 1)',
        'rgba(255, 205, 86, 1)',
        'rgba(255, 99, 132, 1)'
      ],
      borderWidth: 1
    }
  ]
};

const pieOptions = {
  responsive: true,
  plugins: {
    legend: { position: 'bottom' },
    title: { display: true, text: 'Risk Level Distribution' },
  },
};

export default function Dashboard() {
  return (
    <div>
      <h2 className="mb-4">📈 Dashboard</h2>

      {/* Risk Summary Cards */}
      <Row className="mb-4">
        <Col md={4}>
          <Card bg="primary" text="white" className="mb-3 shadow">
            <Card.Body>
              <Card.Title>Total Vendors</Card.Title>
              <Card.Text>100</Card.Text>
            </Card.Body>
          </Card>
        </Col>

        <Col md={4}>
          <Card bg="danger" text="white" className="mb-3 shadow">
            <Card.Body>
              <Card.Title>High Risk Vendors</Card.Title>
              <Card.Text>25</Card.Text>
            </Card.Body>
          </Card>
        </Col>

        <Col md={4}>
          <Card bg="success" text="white" className="mb-3 shadow">
            <Card.Body>
              <Card.Title>AIS Alerts Triggered</Card.Title>
              <Card.Text>5</Card.Text>
            </Card.Body>
          </Card>
        </Col>
      </Row>

      {/* Bar Chart */}
      <div className="mt-5">
        <Bar data={vendorChartData} options={vendorChartOptions} />
      </div>

      {/* Pie Chart */}
      <div className="mt-5">
        <Pie data={pieData} options={pieOptions} />
      </div>
    </div>
  );
}

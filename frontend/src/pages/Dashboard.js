import React, { useEffect, useState } from 'react';
import { Card, Row, Col, Statistic, Table, Tag, Typography } from 'antd';
import { 
  AlertOutlined, 
  CheckCircleOutlined, 
  WarningOutlined,
  ShieldOutlined,
  FileSearchOutlined
} from '@ant-design/icons';
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Legend } from 'recharts';
import { incidentsAPI, dlpAPI, siemAPI } from '../services/api';

const { Title } = Typography;

const COLORS = ['#ff4d4f', '#ff7a45', '#ffa940', '#ffc53d', '#73d13d'];

const Dashboard = () => {
  const [stats, setStats] = useState(null);
  const [dlpStats, setDlpStats] = useState(null);
  const [siemStats, setSiemStats] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchData();
  }, []);

  const fetchData = async () => {
    try {
      const [statsRes, dlpRes, siemRes] = await Promise.all([
        incidentsAPI.getDashboardStats(),
        dlpAPI.getStats(),
        siemAPI.getStats(),
      ]);
      setStats(statsRes.data);
      setDlpStats(dlpRes.data);
      setSiemStats(siemRes.data);
    } catch (error) {
      console.error('Failed to fetch dashboard data:', error);
    } finally {
      setLoading(false);
    }
  };

  const severityData = stats ? Object.entries(stats.incidents_by_severity || {}).map(([key, value]) => ({
    name: key.toUpperCase(),
    value
  })) : [];

  const channelData = stats ? Object.entries(stats.dlp_events_by_channel || {}).map(([key, value]) => ({
    name: key,
    value
  })) : [];

  const topViolators = stats?.top_violators || [];

  return (
    <div>
      <Title level={2}>Security Dashboard</Title>
      
      <Row gutter={[16, 16]} style={{ marginBottom: 24 }}>
        <Col xs={24} sm={12} md={6}>
          <Card>
            <Statistic
              title="Total Incidents"
              value={stats?.total_incidents || 0}
              prefix={<AlertOutlined />}
              valueStyle={{ color: '#1890ff' }}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} md={6}>
          <Card>
            <Statistic
              title="Open Incidents"
              value={stats?.open_incidents || 0}
              prefix={<WarningOutlined />}
              valueStyle={{ color: '#faad14' }}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} md={6}>
          <Card>
            <Statistic
              title="Resolved Incidents"
              value={stats?.resolved_incidents || 0}
              prefix={<CheckCircleOutlined />}
              valueStyle={{ color: '#52c41a' }}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} md={6}>
          <Card>
            <Statistic
              title="Critical Incidents"
              value={stats?.critical_incidents || 0}
              prefix={<ShieldOutlined />}
              valueStyle={{ color: '#ff4d4f' }}
            />
          </Card>
        </Col>
      </Row>

      <Row gutter={[16, 16]} style={{ marginBottom: 24 }}>
        <Col xs={24} sm={12} md={6}>
          <Card>
            <Statistic
              title="DLP Events Today"
              value={stats?.dlp_events_today || 0}
              prefix={<ShieldOutlined />}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} md={6}>
          <Card>
            <Statistic
              title="SIEM Events Today"
              value={stats?.siem_events_today || 0}
              prefix={<FileSearchOutlined />}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} md={6}>
          <Card>
            <Statistic
              title="Blocked DLP Events"
              value={dlpStats?.by_action?.block || 0}
              valueStyle={{ color: '#ff4d4f' }}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} md={6}>
          <Card>
            <Statistic
              title="Quarantined"
              value={dlpStats?.by_action?.quarantine || 0}
              valueStyle={{ color: '#faad14' }}
            />
          </Card>
        </Col>
      </Row>

      <Row gutter={[16, 16]}>
        <Col xs={24} md={12}>
          <Card title="Incidents by Severity">
            <ResponsiveContainer width="100%" height={250}>
              <PieChart>
                <Pie
                  data={severityData}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={80}
                  paddingAngle={5}
                  dataKey="value"
                >
                  {severityData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip />
                <Legend />
              </PieChart>
            </ResponsiveContainer>
          </Card>
        </Col>
        <Col xs={24} md={12}>
          <Card title="DLP Events by Channel">
            <ResponsiveContainer width="100%" height={250}>
              <BarChart data={channelData}>
                <XAxis dataKey="name" />
                <YAxis />
                <Tooltip />
                <Bar dataKey="value" fill="#1890ff" />
              </BarChart>
            </ResponsiveContainer>
          </Card>
        </Col>
      </Row>

      <Row gutter={[16, 16]} style={{ marginTop: 24 }}>
        <Col span={24}>
          <Card title="Top Violators">
            <Table
              dataSource={topViolators}
              columns={[
                { title: 'User', dataIndex: 'user', key: 'user' },
                { title: 'Violation Count', dataIndex: 'count', key: 'count' },
              ]}
              rowKey="user"
              pagination={false}
            />
          </Card>
        </Col>
      </Row>
    </div>
  );
};

export default Dashboard;

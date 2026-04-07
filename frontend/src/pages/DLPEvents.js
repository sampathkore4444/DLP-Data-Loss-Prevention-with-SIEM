import React, { useState, useEffect } from 'react';
import { Table, Tag, Button, Space, Select, message } from 'antd';
import { PlusOutlined } from '@ant-design/icons';
import { dlpAPI } from '../services/api';

const SEVERITY_COLORS = {
  critical: 'red',
  high: 'orange',
  medium: 'gold',
  low: 'green',
};

const CHANNEL_COLORS = {
  email: 'blue',
  web: 'cyan',
  usb: 'purple',
  print: 'magenta',
  network: 'geekblue',
};

const STATUS_COLORS = {
  new: 'blue',
  investigating: 'orange',
  resolved: 'green',
  false_positive: 'default',
};

const DLPEvents = () => {
  const [events, setEvents] = useState([]);
  const [loading, setLoading] = useState(false);
  const [filters, setFilters] = useState({});

  useEffect(() => {
    fetchEvents();
  }, [filters]);

  const fetchEvents = async () => {
    setLoading(true);
    try {
      const response = await dlpAPI.getEvents(filters);
      setEvents(response.data);
    } catch (error) {
      message.error('Failed to fetch DLP events');
    } finally {
      setLoading(false);
    }
  };

  const handleCreateIncident = async (eventId) => {
    try {
      await dlpAPI.createIncident(eventId);
      message.success('Incident created successfully');
      fetchEvents();
    } catch (error) {
      message.error('Failed to create incident');
    }
  };

  const columns = [
    { 
      title: 'Time', 
      dataIndex: 'timestamp', 
      key: 'timestamp',
      render: (text) => new Date(text).toLocaleString() 
    },
    { title: 'User', dataIndex: 'user', key: 'user' },
    { title: 'Data Type', dataIndex: 'data_type', key: 'data_type' },
    { 
      title: 'Channel', 
      dataIndex: 'channel', 
      key: 'channel',
      render: (channel) => <Tag color={CHANNEL_COLORS[channel]}>{channel?.toUpperCase()}</Tag>
    },
    { 
      title: 'Severity', 
      dataIndex: 'severity', 
      key: 'severity',
      render: (severity) => <Tag color={SEVERITY_COLORS[severity]}>{severity?.toUpperCase()}</Tag>
    },
    { 
      title: 'Action', 
      dataIndex: 'action', 
      key: 'action',
      render: (action) => (
        <Tag color={action === 'block' ? 'red' : action === 'quarantine' ? 'orange' : 'green'}>
          {action?.toUpperCase()}
        </Tag>
      )
    },
    { title: 'Source IP', dataIndex: 'source_ip', key: 'source_ip' },
    { title: 'Destination', dataIndex: 'destination', key: 'destination' },
    { 
      title: 'Status', 
      dataIndex: 'status', 
      key: 'status',
      render: (status) => <Tag color={STATUS_COLORS[status]}>{status?.toUpperCase()}</Tag>
    },
    {
      title: 'Actions',
      key: 'actions',
      render: (_, record) => (
        <Button size="small" onClick={() => handleCreateIncident(record.id)}>
          Create Incident
        </Button>
      )
    },
  ];

  return (
    <div>
      <h2>DLP Events</h2>
      <Space style={{ marginBottom: 16 }}>
        <Select
          placeholder="Severity"
          allowClear
          style={{ width: 150 }}
          onChange={(value) => setFilters({ ...filters, severity: value })}
        >
          <Select.Option value="critical">Critical</Select.Option>
          <Select.Option value="high">High</Select.Option>
          <Select.Option value="medium">Medium</Select.Option>
          <Select.Option value="low">Low</Select.Option>
        </Select>
        <Select
          placeholder="Channel"
          allowClear
          style={{ width: 150 }}
          onChange={(value) => setFilters({ ...filters, channel: value })}
        >
          <Select.Option value="email">Email</Select.Option>
          <Select.Option value="web">Web</Select.Option>
          <Select.Option value="usb">USB</Select.Option>
          <Select.Option value="print">Print</Select.Option>
          <Select.Option value="network">Network</Select.Option>
        </Select>
        <Select
          placeholder="Status"
          allowClear
          style={{ width: 150 }}
          onChange={(value) => setFilters({ ...filters, status: value })}
        >
          <Select.Option value="new">New</Select.Option>
          <Select.Option value="investigating">Investigating</Select.Option>
          <Select.Option value="resolved">Resolved</Select.Option>
          <Select.Option value="false_positive">False Positive</Select.Option>
        </Select>
      </Space>
      <Table columns={columns} dataSource={events} rowKey="id" loading={loading} />
    </div>
  );
};

export default DLPEvents;

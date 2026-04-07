import React, { useState, useEffect } from 'react';
import { Table, Tag, Space, Select, Input, Button, message } from 'antd';
import { SearchOutlined } from '@ant-design/icons';
import { siemAPI } from '../services/api';

const SEVERITY_COLORS = {
  critical: 'red',
  high: 'orange',
  medium: 'gold',
  low: 'green',
  info: 'blue',
};

const SIEMEvents = () => {
  const [events, setEvents] = useState([]);
  const [loading, setLoading] = useState(false);
  const [sources, setSources] = useState({});
  const [filters, setFilters] = useState({});
  const [searchQuery, setSearchQuery] = useState('');

  useEffect(() => {
    fetchEvents();
    fetchSources();
  }, [filters]);

  const fetchEvents = async () => {
    setLoading(true);
    try {
      const response = await siemAPI.getEvents(filters);
      setEvents(response.data);
    } catch (error) {
      message.error('Failed to fetch SIEM events');
    } finally {
      setLoading(false);
    }
  };

  const fetchSources = async () => {
    try {
      const response = await siemAPI.getSources();
      setSources(response.data);
    } catch (error) {
      console.error('Failed to fetch sources');
    }
  };

  const handleSearch = async () => {
    if (!searchQuery) return;
    setLoading(true);
    try {
      const response = await siemAPI.searchEvents(searchQuery);
      setEvents(response.data.events || []);
    } catch (error) {
      message.error('Search failed');
    } finally {
      setLoading(false);
    }
  };

  const columns = [
    { 
      title: 'Time', 
      dataIndex: 'timestamp', 
      key: 'timestamp',
      render: (text) => text ? new Date(text).toLocaleString() : '-'
    },
    { title: 'Source', dataIndex: 'source', key: 'source',
      render: (source) => <Tag>{source?.toUpperCase()}</Tag>
    },
    { title: 'Event Type', dataIndex: 'event_type', key: 'event_type' },
    { title: 'User', dataIndex: 'user', key: 'user' },
    { title: 'Host', dataIndex: 'hostname', key: 'hostname' },
    { title: 'Source IP', dataIndex: 'source_ip', key: 'source_ip' },
    { title: 'Dest IP', dataIndex: 'destination_ip', key: 'destination_ip' },
    { 
      title: 'Severity', 
      dataIndex: 'severity', 
      key: 'severity',
      render: (severity) => <Tag color={SEVERITY_COLORS[severity]}>{severity?.toUpperCase()}</Tag>
    },
    { title: 'Message', dataIndex: 'message', key: 'message', ellipsis: true },
  ];

  return (
    <div>
      <h2>SIEM Events</h2>
      <Space style={{ marginBottom: 16 }}>
        <Input 
          placeholder="Search events..." 
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          onPressEnter={handleSearch}
          style={{ width: 250 }}
          prefix={<SearchOutlined />}
        />
        <Button onClick={handleSearch}>Search</Button>
        <Select
          placeholder="Source"
          allowClear
          style={{ width: 150 }}
          onChange={(value) => setFilters({ ...filters, source: value })}
        >
          {Object.keys(sources).map(s => (
            <Select.Option key={s} value={s}>{s}</Select.Option>
          ))}
        </Select>
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
          <Select.Option value="info">Info</Select.Option>
        </Select>
      </Space>
      <Table columns={columns} dataSource={events} rowKey="id" loading={loading} />
    </div>
  );
};

export default SIEMEvents;

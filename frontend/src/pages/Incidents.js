import React, { useState, useEffect } from 'react';
import { Table, Tag, Button, Space, Select, Modal, Form, Input, message, Drawer, Descriptions } from 'antd';
import { PlusOutlined, EyeOutlined } from '@ant-design/icons';
import { incidentsAPI } from '../services/api';

const { TextArea } = Input;

const SEVERITY_COLORS = {
  critical: 'red',
  high: 'orange',
  medium: 'gold',
  low: 'green',
};

const STATUS_COLORS = {
  new: 'blue',
  investigating: 'orange',
  resolved: 'green',
  false_positive: 'default',
  escalated: 'red',
};

const Incidents = () => {
  const [incidents, setIncidents] = useState([]);
  const [loading, setLoading] = useState(false);
  const [filters, setFilters] = useState({});
  const [modalVisible, setModalVisible] = useState(false);
  const [drawerVisible, setDrawerVisible] = useState(false);
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [form] = Form.useForm();

  useEffect(() => {
    fetchIncidents();
  }, [filters]);

  const fetchIncidents = async () => {
    setLoading(true);
    try {
      const response = await incidentsAPI.getIncidents(filters);
      setIncidents(response.data);
    } catch (error) {
      message.error('Failed to fetch incidents');
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = async (values) => {
    try {
      await incidentsAPI.createIncident(values);
      message.success('Incident created successfully');
      setModalVisible(false);
      form.resetFields();
      fetchIncidents();
    } catch (error) {
      message.error('Failed to create incident');
    }
  };

  const handleView = async (record) => {
    try {
      const response = await incidentsAPI.getIncident(record.id);
      setSelectedIncident(response.data);
      setDrawerVisible(true);
    } catch (error) {
      message.error('Failed to fetch incident details');
    }
  };

  const handleStatusChange = async (id, status) => {
    try {
      await incidentsAPI.updateIncident(id, { status });
      message.success('Status updated');
      fetchIncidents();
    } catch (error) {
      message.error('Failed to update status');
    }
  };

  const columns = [
    { title: 'Incident ID', dataIndex: 'incident_id', key: 'incident_id', width: 150 },
    { title: 'Title', dataIndex: 'title', key: 'title', ellipsis: true },
    { title: 'Source', dataIndex: 'source', key: 'source',
      render: (source) => <Tag>{source?.toUpperCase()}</Tag>
    },
    { 
      title: 'Severity', 
      dataIndex: 'severity', 
      key: 'severity',
      render: (severity) => <Tag color={SEVERITY_COLORS[severity]}>{severity?.toUpperCase()}</Tag>
    },
    { 
      title: 'Status', 
      dataIndex: 'status', 
      key: 'status',
      render: (status) => <Tag color={STATUS_COLORS[status]}>{status?.toUpperCase()}</Tag>
    },
    { 
      title: 'Created', 
      dataIndex: 'created_at', 
      key: 'created_at',
      render: (text) => new Date(text).toLocaleString()
    },
    {
      title: 'Actions',
      key: 'actions',
      render: (_, record) => (
        <Space>
          <Button icon={<EyeOutlined />} size="small" onClick={() => handleView(record)} />
          <Select
            size="small"
            value={record.status}
            onChange={(value) => handleStatusChange(record.id, value)}
            style={{ width: 120 }}
          >
            <Select.Option value="new">New</Select.Option>
            <Select.Option value="investigating">Investigating</Select.Option>
            <Select.Option value="resolved">Resolved</Select.Option>
            <Select.Option value="false_positive">False Positive</Select.Option>
          </Select>
        </Space>
      )
    },
  ];

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 16 }}>
        <h2>Incidents</h2>
        <Button type="primary" icon={<PlusOutlined />} onClick={() => setModalVisible(true)}>
          Create Incident
        </Button>
      </div>
      
      <Space style={{ marginBottom: 16 }}>
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
      </Space>

      <Table columns={columns} dataSource={incidents} rowKey="id" loading={loading} />
      
      <Modal
        title="Create Incident"
        open={modalVisible}
        onCancel={() => { setModalVisible(false); form.resetFields(); }}
        onOk={form.submit}
      >
        <Form form={form} layout="vertical" onFinish={handleSubmit}>
          <Form.Item name="title" label="Title" rules={[{ required: true }]}>
            <Input />
          </Form.Item>
          <Form.Item name="description" label="Description">
            <TextArea rows={3} />
          </Form.Item>
          <Form.Item name="severity" label="Severity" rules={[{ required: true }]}>
            <Select>
              <Select.Option value="critical">Critical</Select.Option>
              <Select.Option value="high">High</Select.Option>
              <Select.Option value="medium">Medium</Select.Option>
              <Select.Option value="low">Low</Select.Option>
            </Select>
          </Form.Item>
          <Form.Item name="source" label="Source" rules={[{ required: true }]}>
            <Select>
              <Select.Option value="dlp">DLP</Select.Option>
              <Select.Option value="siem">SIEM</Select.Option>
              <Select.Option value="manual">Manual</Select.Option>
            </Select>
          </Form.Item>
        </Form>
      </Modal>

      <Drawer
        title="Incident Details"
        width={600}
        open={drawerVisible}
        onClose={() => setDrawerVisible(false)}
      >
        {selectedIncident && (
          <Descriptions column={1} bordered>
            <Descriptions.Item label="Incident ID">{selectedIncident.incident_id}</Descriptions.Item>
            <Descriptions.Item label="Title">{selectedIncident.title}</Descriptions.Item>
            <Descriptions.Item label="Description">{selectedIncident.description}</Descriptions.Item>
            <Descriptions.Item label="Severity">
              <Tag color={SEVERITY_COLORS[selectedIncident.severity]}>{selectedIncident.severity?.toUpperCase()}</Tag>
            </Descriptions.Item>
            <Descriptions.Item label="Status">
              <Tag color={STATUS_COLORS[selectedIncident.status]}>{selectedIncident.status?.toUpperCase()}</Tag>
            </Descriptions.Item>
            <Descriptions.Item label="Source">{selectedIncident.source}</Descriptions.Item>
            <Descriptions.Item label="Created">{new Date(selectedIncident.created_at).toLocaleString()}</Descriptions.Item>
            <Descriptions.Item label="Notes">{selectedIncident.notes}</Descriptions.Item>
          </Descriptions>
        )}
      </Drawer>
    </div>
  );
};

export default Incidents;

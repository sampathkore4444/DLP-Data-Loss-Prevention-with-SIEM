import React, { useState, useEffect } from 'react';
import { Table, Button, Modal, Form, Input, Select, Tag, Space, message, Popconfirm } from 'antd';
import { PlusOutlined, EditOutlined, DeleteOutlined } from '@ant-design/icons';
import { dlpAPI } from '../services/api';

const { TextArea } = Input;

const DATA_TYPES = [
  { value: 'credit_card', label: 'Credit Card' },
  { value: 'ssn', label: 'Social Security Number' },
  { value: 'account_number', label: 'Account Number' },
  { value: 'routing_number', label: 'Routing Number' },
  { value: 'password', label: 'Password' },
  { value: 'custom', label: 'Custom Pattern' },
];

const CHANNELS = [
  { value: 'email', label: 'Email' },
  { value: 'web', label: 'Web' },
  { value: 'usb', label: 'USB' },
  { value: 'print', label: 'Print' },
  { value: 'network', label: 'Network' },
];

const ACTIONS = [
  { value: 'allow', label: 'Allow' },
  { value: 'block', label: 'Block' },
  { value: 'quarantine', label: 'Quarantine' },
  { value: 'notify', label: 'Notify Only' },
];

const SEVERITIES = [
  { value: 'critical', label: 'Critical', color: 'red' },
  { value: 'high', label: 'High', color: 'orange' },
  { value: 'medium', label: 'Medium', color: 'gold' },
  { value: 'low', label: 'Low', color: 'green' },
];

const DLPPolicies = () => {
  const [policies, setPolicies] = useState([]);
  const [loading, setLoading] = useState(false);
  const [modalVisible, setModalVisible] = useState(false);
  const [editingPolicy, setEditingPolicy] = useState(null);
  const [form] = Form.useForm();

  useEffect(() => {
    fetchPolicies();
  }, []);

  const fetchPolicies = async () => {
    setLoading(true);
    try {
      const response = await dlpAPI.getPolicies();
      setPolicies(response.data);
    } catch (error) {
      message.error('Failed to fetch policies');
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = async (values) => {
    try {
      if (editingPolicy) {
        await dlpAPI.updatePolicy(editingPolicy.id, values);
        message.success('Policy updated successfully');
      } else {
        await dlpAPI.createPolicy(values);
        message.success('Policy created successfully');
      }
      setModalVisible(false);
      form.resetFields();
      setEditingPolicy(null);
      fetchPolicies();
    } catch (error) {
      message.error(error.response?.data?.detail || 'Operation failed');
    }
  };

  const handleEdit = (record) => {
    setEditingPolicy(record);
    form.setFieldsValue(record);
    setModalVisible(true);
  };

  const handleDelete = async (id) => {
    try {
      await dlpAPI.deletePolicy(id);
      message.success('Policy deleted successfully');
      fetchPolicies();
    } catch (error) {
      message.error('Failed to delete policy');
    }
  };

  const columns = [
    { title: 'Name', dataIndex: 'name', key: 'name' },
    { title: 'Data Type', dataIndex: 'data_type', key: 'data_type' },
    { title: 'Channel', dataIndex: 'channel', key: 'channel' },
    { title: 'Action', dataIndex: 'action', key: 'action', 
      render: (action) => (
        <Tag color={action === 'block' ? 'red' : action === 'quarantine' ? 'orange' : 'green'}>
          {action.toUpperCase()}
        </Tag>
      )
    },
    { title: 'Severity', dataIndex: 'severity', key: 'severity',
      render: (severity) => {
        const sev = SEVERITIES.find(s => s.value === severity);
        return <Tag color={sev?.color}>{severity?.toUpperCase()}</Tag>;
      }
    },
    { title: 'Status', dataIndex: 'enabled', key: 'enabled',
      render: (enabled) => (
        <Tag color={enabled ? 'green' : 'red'}>{enabled ? 'Enabled' : 'Disabled'}</Tag>
      )
    },
    { title: 'Action', key: 'action',
      render: (_, record) => (
        <Space>
          <Button icon={<EditOutlined />} size="small" onClick={() => handleEdit(record)} />
          <Popconfirm title="Are you sure?" onConfirm={() => handleDelete(record.id)}>
            <Button icon={<DeleteOutlined />} size="small" danger />
          </Popconfirm>
        </Space>
      )
    },
  ];

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 16 }}>
        <h2>DLP Policies</h2>
        <Button type="primary" icon={<PlusOutlined />} onClick={() => { setEditingPolicy(null); form.resetFields(); setModalVisible(true); }}>
          Add Policy
        </Button>
      </div>
      <Table columns={columns} dataSource={policies} rowKey="id" loading={loading} />
      
      <Modal
        title={editingPolicy ? 'Edit Policy' : 'Create Policy'}
        open={modalVisible}
        onCancel={() => { setModalVisible(false); setEditingPolicy(null); form.resetFields(); }}
        onOk={form.submit}
      >
        <Form form={form} layout="vertical" onFinish={handleSubmit}>
          <Form.Item name="name" label="Policy Name" rules={[{ required: true }]}>
            <Input />
          </Form.Item>
          <Form.Item name="description" label="Description">
            <TextArea rows={2} />
          </Form.Item>
          <Form.Item name="data_type" label="Data Type" rules={[{ required: true }]}>
            <Select options={DATA_TYPES} />
          </Form.Item>
          <Form.Item name="channel" label="Channel" rules={[{ required: true }]}>
            <Select options={CHANNELS} />
          </Form.Item>
          <Form.Item name="pattern" label="Pattern (Regex)" rules={[{ required: true }]}>
            <TextArea rows={2} placeholder="e.g., \d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}" />
          </Form.Item>
          <Form.Item name="action" label="Action" rules={[{ required: true }]}>
            <Select options={ACTIONS} />
          </Form.Item>
          <Form.Item name="severity" label="Severity" rules={[{ required: true }]}>
            <Select options={SEVERITIES} />
          </Form.Item>
          <Form.Item name="enabled" label="Enabled" valuePropName="checked">
            <input type="checkbox" />
          </Form.Item>
        </Form>
      </Modal>
    </div>
  );
};

export default DLPPolicies;

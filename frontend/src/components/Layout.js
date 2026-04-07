import React from 'react';
import { Outlet, useNavigate, useLocation } from 'react-router-dom';
import { Layout as AntLayout, Menu, Avatar, Dropdown, Space, Typography } from 'antd';
import {
  DashboardOutlined,
  ShieldOutlined,
  AlertOutlined,
  FileSearchOutlined,
  UserOutlined,
  LogoutOutlined,
} from '@ant-design/icons';

const { Header, Sider, Content } = AntLayout;
const { Title } = Typography;

const Layout = () => {
  const navigate = useNavigate();
  const location = useLocation();

  const menuItems = [
    {
      key: '/',
      icon: <DashboardOutlined />,
      label: 'Dashboard',
    },
    {
      key: '/dlp/policies',
      icon: <ShieldOutlined />,
      label: 'DLP Policies',
    },
    {
      key: '/dlp/events',
      icon: <AlertOutlined />,
      label: 'DLP Events',
    },
    {
      key: '/siem/events',
      icon: <FileSearchOutlined />,
      label: 'SIEM Events',
    },
    {
      key: '/incidents',
      icon: <AlertOutlined />,
      label: 'Incidents',
    },
  ];

  const userMenu = {
    items: [
      {
        key: 'profile',
        icon: <UserOutlined />,
        label: 'Profile',
      },
      {
        key: 'logout',
        icon: <LogoutOutlined />,
        label: 'Logout',
        onClick: () => {
          localStorage.removeItem('access_token');
          localStorage.removeItem('refresh_token');
          navigate('/login');
        },
      },
    ],
  };

  return (
    <AntLayout style={{ minHeight: '100vh' }}>
      <Sider theme="dark" width={250}>
        <div style={{ padding: '20px', textAlign: 'center' }}>
          <ShieldOutlined style={{ fontSize: 32, color: '#1890ff' }} />
          <Title level={4} style={{ color: 'white', marginTop: 10, marginBottom: 0 }}>
            SecureVault
          </Title>
          <div style={{ color: '#8c8c8c', fontSize: 12 }}>DLP & SIEM</div>
        </div>
        <Menu
          theme="dark"
          mode="inline"
          selectedKeys={[location.pathname]}
          items={menuItems}
          onClick={({ key }) => navigate(key)}
        />
      </Sider>
      <AntLayout>
        <Header style={{ background: '#fff', padding: '0 24px', display: 'flex', justifyContent: 'flex-end', alignItems: 'center' }}>
          <Dropdown menu={userMenu} placement="bottomRight">
            <Space style={{ cursor: 'pointer' }}>
              <Avatar icon={<UserOutlined />} />
              <span>Admin</span>
            </Space>
          </Dropdown>
        </Header>
        <Content style={{ margin: 24, padding: 24, background: '#fff', borderRadius: 8 }}>
          <Outlet />
        </Content>
      </AntLayout>
    </AntLayout>
  );
};

export default Layout;

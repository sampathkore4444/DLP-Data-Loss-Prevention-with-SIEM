import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { ConfigProvider } from 'antd';
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import DLPPolicies from './pages/DLPPolicies';
import DLPEvents from './pages/DLPEvents';
import SIEMEvents from './pages/SIEMEvents';
import Incidents from './pages/Incidents';
import Layout from './components/Layout';

const PrivateRoute = ({ children }) => {
  const token = localStorage.getItem('access_token');
  return token ? children : <Navigate to="/login" />;
};

function App() {
  return (
    <ConfigProvider
      theme={{
        token: {
          colorPrimary: '#1890ff',
          borderRadius: 4,
        },
      }}
    >
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route
            path="/"
            element={
              <PrivateRoute>
                <Layout />
              </PrivateRoute>
            }
          >
            <Route index element={<Dashboard />} />
            <Route path="dlp/policies" element={<DLPPolicies />} />
            <Route path="dlp/events" element={<DLPEvents />} />
            <Route path="siem/events" element={<SIEMEvents />} />
            <Route path="incidents" element={<Incidents />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </ConfigProvider>
  );
}

export default App;

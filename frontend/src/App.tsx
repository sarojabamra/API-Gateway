import React from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { MainLayout } from './components/layout/MainLayout';
import { LoginPage } from './pages/LoginPage';
import { OverviewPage } from './pages/OverviewPage';
import { LiveTrafficPage } from './pages/LiveTrafficPage';
import { AlertsPage } from './pages/AlertsPage';
import { AlertDetailPage } from './pages/AlertDetailPage';
import { PoliciesPage } from './pages/PoliciesPage';
import { RateLimitsPage } from './pages/RateLimitsPage';
import { InventoryPage } from './pages/InventoryPage';
import { AuthSettingsPage } from './pages/AuthSettingsPage';
import { BlocklistPage } from './pages/BlocklistPage';
import { AnalyticsPage } from './pages/AnalyticsPage';
import { AttackSimulatorPage } from './pages/AttackSimulatorPage';
import { ReportsPage } from './pages/ReportsPage';
import { SettingsUsersPage } from './pages/SettingsUsersPage';
import { NotFoundForbiddenPage } from './pages/NotFoundForbiddenPage';

export const App: React.FC = () => {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route path="/" element={<MainLayout />}>
          <Route index element={<OverviewPage />} />
          <Route path="traffic" element={<LiveTrafficPage />} />
          <Route path="alerts" element={<AlertsPage />} />
          <Route path="alerts/:id" element={<AlertDetailPage />} />
          <Route path="policies" element={<PoliciesPage />} />
          <Route path="rate-limits" element={<RateLimitsPage />} />
          <Route path="inventory" element={<InventoryPage />} />
          <Route path="auth-settings" element={<AuthSettingsPage />} />
          <Route path="blocklist" element={<BlocklistPage />} />
          <Route path="analytics" element={<AnalyticsPage />} />
          <Route path="owasp" element={<AttackSimulatorPage />} />
          <Route path="simulator" element={<AttackSimulatorPage />} />
          <Route path="reports" element={<ReportsPage />} />
          <Route path="settings" element={<SettingsUsersPage />} />
          <Route path="forbidden" element={<NotFoundForbiddenPage mode="403" />} />
          <Route path="*" element={<NotFoundForbiddenPage mode="404" />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
};

export default App;

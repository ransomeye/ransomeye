import { useEffect } from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import { Layout } from './components/Layout';
import { EventFeed } from './components/EventFeed';
import { Alerts } from './components/Alerts';
import { Dashboard } from './pages/Dashboard';
import { Detections } from './pages/Detections';
import { Incidents } from './pages/Incidents';
import { Explainability } from './pages/Explainability';
import { Governance } from './pages/Governance';
import { Fleet } from './pages/Fleet';
import { Compliance } from './pages/Compliance';
import { SystemHealth } from './pages/SystemHealth';
import { IngestionStatus } from './pages/IngestionStatus';
import { RealTimeStream } from './pages/RealTimeStream';
import { ShadowIntelligence } from './pages/ShadowIntelligence';
import { AssetCoverage } from './pages/AssetCoverage';
import { ExecutiveSummary } from './pages/ExecutiveSummary';
import { enforceHttpsConstraints } from './lib/client';

export default function App() {
  useEffect(() => {
    enforceHttpsConstraints();
  }, []);

  return (
    <Routes>
      <Route path="/" element={<Layout />}>
        <Route index element={<Navigate to="/dashboard" replace />} />
        <Route path="dashboard" element={<Dashboard />} />
        <Route path="event-feed" element={<EventFeed />} />
        <Route path="alerts" element={<Alerts />} />
        <Route path="incidents-panel" element={<Navigate to="/incidents" replace />} />
        <Route path="system-health" element={<SystemHealth />} />
        <Route path="detections" element={<Detections />} />
        <Route path="incidents" element={<Incidents />} />
        <Route path="explainability" element={<Explainability />} />
        <Route path="governance" element={<Governance />} />
        <Route path="fleet" element={<Fleet />} />
        <Route path="compliance" element={<Compliance />} />
        <Route path="health" element={<SystemHealth />} />
        <Route path="ingestion" element={<IngestionStatus />} />
        <Route path="stream" element={<RealTimeStream />} />
        <Route path="shadow-intelligence" element={<ShadowIntelligence />} />
        <Route path="asset-coverage" element={<AssetCoverage />} />
        <Route path="executive" element={<ExecutiveSummary />} />
        <Route path="*" element={<Navigate to="/dashboard" replace />} />
      </Route>
    </Routes>
  );
}

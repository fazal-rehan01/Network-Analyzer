import { lazy } from "react";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { Layout } from "@/components/Layout";

const Dashboard = lazy(() => import("@/pages/Dashboard"));
const SimulationPage = lazy(() => import("@/pages/SimulationPage").then((m) => ({ default: m.SimulationPage })));
const CapturePage = lazy(() => import("@/pages/CapturePage").then((m) => ({ default: m.CapturePage })));
const PacketsPage = lazy(() => import("@/pages/PacketsPage").then((m) => ({ default: m.PacketsPage })));
const ZeekPage = lazy(() => import("@/pages/ZeekPage").then((m) => ({ default: m.ZeekPage })));
const CorrelatedPage = lazy(() => import("@/pages/CorrelatedPage").then((m) => ({ default: m.CorrelatedPage })));
const DetectPage = lazy(() => import("@/pages/DetectPage").then((m) => ({ default: m.DetectPage })));
const IncidentsPage = lazy(() => import("@/pages/IncidentsPage").then((m) => ({ default: m.IncidentsPage })));
const ComparePage = lazy(() => import("@/pages/ComparePage").then((m) => ({ default: m.ComparePage })));
const ReportsPage = lazy(() => import("@/pages/ReportsPage").then((m) => ({ default: m.ReportsPage })));
const SystemPage = lazy(() => import("@/pages/SystemPage").then((m) => ({ default: m.SystemPage })));

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<Layout />}>
          <Route path="/" element={<Dashboard />} />
          <Route path="/simulation" element={<SimulationPage />} />
          <Route path="/capture" element={<CapturePage />} />
          <Route path="/packets" element={<PacketsPage />} />
          <Route path="/zeek" element={<ZeekPage />} />
          <Route path="/correlated" element={<CorrelatedPage />} />
          <Route path="/detect" element={<DetectPage />} />
          <Route path="/incidents" element={<IncidentsPage />} />
          <Route path="/compare" element={<ComparePage />} />
          <Route path="/reports" element={<ReportsPage />} />
          <Route path="/system" element={<SystemPage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
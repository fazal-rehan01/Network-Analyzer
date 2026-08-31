import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { Layout } from "@/components/Layout";
import Dashboard from "@/pages/Dashboard";
import { SimulationPage } from "@/pages/SimulationPage";
import { PacketsPage } from "@/pages/PacketsPage";
import { ZeekPage } from "@/pages/ZeekPage";
import { ComparePage } from "@/pages/ComparePage";
import { AlertsPage } from "@/pages/AlertsPage";
import { ReportsPage } from "@/pages/ReportsPage";
import { SystemPage } from "@/pages/SystemPage";

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<Layout />}>
          <Route path="/" element={<Dashboard />} />
          <Route path="/simulation" element={<SimulationPage />} />
          <Route path="/packets" element={<PacketsPage />} />
          <Route path="/zeek" element={<ZeekPage />} />
          <Route path="/compare" element={<ComparePage />} />
          <Route path="/alerts" element={<AlertsPage />} />
          <Route path="/reports" element={<ReportsPage />} />
          <Route path="/system" element={<SystemPage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}

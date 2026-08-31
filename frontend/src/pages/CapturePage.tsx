import { useState } from "react";
import { api } from "@/api/client";
import { Badge, Card, EmptyState, ErrorState, Spinner } from "@/components/ui";
import { useApi } from "@/hooks/useApi";
import type { CaptureCreate } from "@/api/types";

export function CapturePage() {
  const ifaces = useApi(() => api.captureInterfaces(), 30000);
  const captures = useApi(() => api.captureList(), 5000);
  const [newCapture, setNewCapture] = useState<CaptureCreate>({
    interface_index: 0,
    filter_expr: "",
    duration_sec: 30,
    name: "",
  });
  const [starting, setStarting] = useState(false);
  const [startError, setStartError] = useState<string | null>(null);

  const handleStart = async () => {
    if (!newCapture.interface_index) {
      setStartError("Select an interface");
      return;
    }
    setStarting(true);
    setStartError(null);
    try {
      await api.captureStart(newCapture);
      setNewCapture({ ...newCapture, name: "", filter_expr: "" });
      captures.refetch();
    } catch (e) {
      setStartError(e instanceof Error ? e.message : "Failed to start capture");
    } finally {
      setStarting(false);
    }
  };

  const handleStop = async (id: string) => {
    try {
      await api.captureStop(id);
      captures.refetch();
    } catch (e) {
      // ignore, UI will refresh
    }
  };

  const handleDelete = async (id: string) => {
    try {
      await api.captureDelete(id);
      captures.refetch();
    } catch (e) {
      // ignore
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold">Live Packet Capture</h1>
        <p className="text-sm text-slate-400">Start TShark captures on lab interfaces. Captures persist as PCAP files for analysis.</p>
      </div>

      <Card title="Start New Capture" actions={
        <span className="text-[11px] text-slate-500">
          {ifaces.loading ? "Loading interfaces…" : ifaces.data?.length === 0 ? "No interfaces" : `${ifaces.data?.length} interfaces`}
        </span>
      }>
        {ifaces.loading ? (
          <Spinner />
        ) : ifaces.error ? (
          <ErrorState message={ifaces.error} onRetry={ifaces.refetch} />
        ) : ifaces.data && ifaces.data.length === 0 ? (
          <EmptyState message="No capture interfaces found. TShark may not be installed." />
        ) : (
          <div className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
              <div>
                <label className="block text-xs text-slate-400 mb-1">Interface</label>
                <select
                  value={newCapture.interface_index}
                  onChange={(e) => setNewCapture({ ...newCapture, interface_index: Number(e.target.value) })}
                  className="w-full rounded-lg border border-slate-700 bg-slate-900/50 px-3 py-2 text-sm text-slate-100 focus:outline-none focus:ring-1 focus:ring-cyan-500"
                >
                  <option value={0}>Select interface…</option>
                  {ifaces.data?.map((iface) => (
                    <option key={iface.index} value={iface.index}>
                      {iface.index}. {iface.name} — {iface.description ?? "—"}
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label className="block text-xs text-slate-400 mb-1">Capture Name</label>
                <input
                  type="text"
                  value={newCapture.name}
                  onChange={(e) => setNewCapture({ ...newCapture, name: e.target.value })}
                  placeholder="Live capture"
                  className="w-full rounded-lg border border-slate-700 bg-slate-900/50 px-3 py-2 text-sm text-slate-100 focus:outline-none focus:ring-1 focus:ring-cyan-500"
                />
              </div>
              <div>
                <label className="block text-xs text-slate-400 mb-1">BPF Filter (optional)</label>
                <input
                  type="text"
                  value={newCapture.filter_expr}
                  onChange={(e) => setNewCapture({ ...newCapture, filter_expr: e.target.value })}
                  placeholder="e.g., tcp port 80 or udp port 53"
                  className="w-full rounded-lg border border-slate-700 bg-slate-900/50 px-3 py-2 text-sm text-slate-100 focus:outline-none focus:ring-1 focus:ring-cyan-500"
                />
              </div>
              <div>
                <label className="block text-xs text-slate-400 mb-1">Auto-stop (seconds)</label>
                <input
                  type="number"
                  min={5}
                  max={3600}
                  value={newCapture.duration_sec}
                  onChange={(e) => setNewCapture({ ...newCapture, duration_sec: Number(e.target.value) || 30 })}
                  className="w-full rounded-lg border border-slate-700 bg-slate-900/50 px-3 py-2 text-sm text-slate-100 focus:outline-none focus:ring-1 focus:ring-cyan-500"
                />
              </div>
            </div>
            {startError && (
              <div className="text-rose-300 text-sm">{startError}</div>
            )}
            <button
              onClick={handleStart}
              disabled={starting || !newCapture.interface_index}
              className="px-4 py-2 rounded-lg bg-cyan-500/10 text-cyan-300 text-sm font-medium hover:bg-cyan-500/20 disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
            >
              {starting ? <Spinner label="Starting…" /> : <>Start Capture</>}
            </button>
          </div>
        )}
      </Card>

      <Card title="Captures">
        {captures.loading ? (
          <Spinner />
        ) : captures.error ? (
          <ErrorState message={captures.error} onRetry={captures.refetch} />
        ) : captures.data && captures.data.length === 0 ? (
          <EmptyState message="No captures yet. Start a live capture above." />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-xs uppercase text-slate-500 border-b border-slate-800">
                  <th className="py-2 pr-4">Name</th>
                  <th className="py-2 pr-4">Interface</th>
                  <th className="py-2 pr-4">Status</th>
                  <th className="py-2 pr-4">Packets</th>
                  <th className="py-2 pr-4">Bytes</th>
                  <th className="py-2 pr-4">Duration</th>
                  <th className="py-2 pr-4">Started</th>
                  <th className="py-2">Actions</th>
                </tr>
              </thead>
              <tbody>
                {captures.data?.map((cap) => (
                  <tr key={cap.id} className="border-b border-slate-800/60 last:border-0">
                    <td className="py-2.5 pr-4 font-medium text-slate-200">{cap.name}</td>
                    <td className="py-2.5 pr-4 text-slate-400">{cap.interface ?? "—"}</td>
                    <td className="py-2.5 pr-4">
                      <Badge
                        tone={
                          cap.status === "running" ? "cyan" :
                          cap.status === "done" ? "emerald" :
                          cap.status === "error" ? "rose" :
                          "amber"
                        }
                      >
                        {cap.status}
                      </Badge>
                    </td>
                    <td className="py-2.5 pr-4 text-slate-300">{cap.packet_count.toLocaleString()}</td>
                    <td className="py-2.5 pr-4 text-slate-300">
                      {cap.byte_count > 0 ? `${(cap.byte_count / 1024).toFixed(1)} KB` : "—"}
                    </td>
                    <td className="py-2.5 pr-4 text-slate-400">
                      {cap.duration_sec ? `${cap.duration_sec.toFixed(1)} s` : "—"}
                    </td>
                    <td className="py-2.5 pr-4 text-slate-400">
                      {cap.start_time ? new Date(cap.start_time).toLocaleTimeString() : "—"}
                    </td>
                    <td className="py-2.5">
                      <div className="flex items-center gap-2">
                        {cap.status === "running" ? (
                          <button
                            onClick={() => handleStop(cap.id)}
                            className="px-2 py-1 rounded bg-amber-500/10 text-amber-300 text-[11px] hover:bg-amber-500/20"
                          >
                            Stop
                          </button>
                        ) : (
                          <>
                            <button
                              onClick={() => handleDelete(cap.id)}
                              className="px-2 py-1 rounded bg-rose-500/10 text-rose-300 text-[11px] hover:bg-rose-500/20"
                            >
                              Delete
                            </button>
                            {cap.status === "done" && cap.packet_count > 0 && (
                              <CaptureStatsInline captureId={cap.id} />
                            )}
                          </>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {ifaces.data?.length === 0 && !ifaces.loading && !ifaces.error && (
        <Card title="TShark Not Available">
          <div className="text-sm text-slate-400 space-y-2">
            <p>Live capture requires <strong>TShark</strong> (part of Wireshark).</p>
            <p>Install Wireshark from <a href="https://www.wireshark.org/download.html" className="text-cyan-400 hover:underline" target="_blank" rel="noopener">wireshark.org</a>.</p>
            <p>On Windows, ensure Npcap is installed (included in Wireshark installer) for loopback capture.</p>
          </div>
        </Card>
      )}
    </div>
  );
}

function CaptureStatsInline({ captureId }: { captureId: string }) {
  const stats = useApi(() => api.captureStats(captureId), 0);
  if (stats.loading || !stats.data) return null;
  return (
    <div className="ml-2 flex items-center gap-2">
      <span className="text-[11px] text-slate-500">{stats.data.packet_count} pkts</span>
      <span className="text-[11px] text-slate-500">|</span>
      <span className="text-[11px] text-slate-500">
        {stats.data.protocols.length} protocols
      </span>
    </div>
  );
}
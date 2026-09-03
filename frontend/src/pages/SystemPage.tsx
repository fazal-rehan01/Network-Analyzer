import { api } from "@/api/client";
import { Badge, Card, ErrorState, Spinner } from "@/components/ui";
import { useApi } from "@/hooks/useApi";

export function SystemPage() {
  const sys = useApi(() => api.systemStatus(), 20000);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold">System Status</h1>
        <p className="text-sm text-slate-400">Availability of tools used by the analysis pipeline.</p>
      </div>
      <Card>
        {sys.loading ? (
          <Spinner />
        ) : sys.error ? (
          <ErrorState message={sys.error} onRetry={sys.refetch} />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-xs uppercase text-slate-500 border-b border-slate-800">
                  <th className="py-2 pr-4">Component</th>
                  <th className="py-2 pr-4">Status</th>
                  <th className="py-2 pr-4">Version</th>
                  <th className="py-2 pr-4">Path</th>
                  <th className="py-2">Notes</th>
                </tr>
              </thead>
              <tbody>
                {sys.data?.components.map((c) => (
                  <tr key={c.name} className="border-b border-slate-800/60 last:border-0">
                    <td className="py-2.5 pr-4 font-medium text-slate-200">{c.name}</td>
                    <td className="py-2.5 pr-4">
                      <Badge tone={c.installed ? "emerald" : "rose"}>
                        {c.installed ? "Installed" : "Missing"}
                      </Badge>
                    </td>
                    <td className="py-2.5 pr-4 text-slate-400">{c.version ?? "—"}</td>
                    <td className="py-2.5 pr-4 text-slate-400 max-w-[260px] truncate" title={c.path ?? undefined}>
                      {c.path ?? "—"}
                    </td>
                    <td className="py-2.5 text-slate-500">{c.note ?? "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
      <Card title="What a missing tool means">
        <div className="text-sm text-slate-400 space-y-2">
          <p>
            <span className="font-medium text-slate-200">TShark</span> — required for live packet capture and PCAP
            parsing. Without it, upload/capture features are disabled but the rest of the app keeps working.
          </p>
          <p>
            <span className="font-medium text-slate-200">Zeek</span> — optional. Adds connection/event analysis.
            Without it, the app reports it unavailable and skips Zeek steps.
          </p>
          <p>
            <span className="font-medium text-slate-200">Docker</span> — optional. Used to spin up lab target
            containers for controlled simulations.
          </p>
        </div>
      </Card>
    </div>
  );
}

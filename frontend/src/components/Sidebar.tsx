import { NavLink } from "react-router-dom";

const NAV = [
  { to: "/", label: "Dashboard", icon: "M4 5a1 1 0 011-1h14a1 1 0 011 1v14a1 1 0 01-1 1H5a1 1 0 01-1-1V5z" },
  { to: "/simulation", label: "Simulation", icon: "M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v8a2 2 0 002 2z" },
  { to: "/packets", label: "Packets", icon: "M20 7l-8-4-8 4m16 0l-8 4m8-4v10l-8 4m0-10L4 7m8 4v10M4 7v10l8 4" },
  { to: "/zeek", label: "Zeek", icon: "M13 10V3L4 14h7v7l9-11h-7z" },
  { to: "/compare", label: "Compare", icon: "M11 4H4v11h7V4zM20 9h-7v6h7V9zM11 17H4v3h7v-3zM20 17h-7v3h7v-3z" },
  { to: "/alerts", label: "Alerts", icon: "M12 3v2m0 14v2m-7-9H3m18 0h-2M6 6l1.5 1.5M18 6l-1.5 1.5M6 12a6 6 0 1012 0 6 6 0 00-12 0z" },
  { to: "/reports", label: "Reports", icon: "M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.6a2 2 0 011.4.6l4.4 4.4a2 2 0 01.6 1.4V19a2 2 0 01-2 2z" },
  { to: "/system", label: "System", icon: "M12 15a3 3 0 100-6 3 3 0 000 6z M19 12a7 7 0 00-.1-1.2l2.1-1.6-2-3.4-2.5 1a7 7 0 00-2-1.2L14.2 3h-4l-.3 2.6a7 7 0 00-2 1.2l-2.5-1-2 3.4 2.1 1.6A7 7 0 005 12c0 .4 0 .8.1 1.2l-2.1 1.6 2 3.4 2.5-1a7 7 0 002 1.2l.3 2.6h4l.3-2.6a7 7 0 002-1.2l2.5 1 2-3.4-2.1-1.6c.1-.4.1-.8.1-1.2z" },
];

function NavButton({ to, label, icon }: { to: string; label: string; icon: string }) {
  return (
    <NavLink
      to={to}
      className={({ isActive }) =>
        `flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
          isActive
            ? "bg-cyan-500/10 text-cyan-300 border-l-2 border-cyan-400"
            : "text-slate-400 hover:bg-slate-800/60 hover:text-slate-200"
        }`
      }
    >
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="w-5 h-5 shrink-0">
        <path d={icon} strokeLinecap="round" strokeLinejoin="round" />
      </svg>
      <span>{label}</span>
    </NavLink>
  );
}

export function Sidebar() {
  return (
    <aside className="w-60 shrink-0 border-r border-slate-800 bg-slate-900/60 flex flex-col">
      <div className="px-4 py-5 border-b border-slate-800">
        <div className="flex items-center gap-2">
          <div className="w-8 h-8 rounded-md bg-cyan-500/20 flex items-center justify-center text-cyan-400">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" className="w-5 h-5">
              <path d="M20 7l-8-4-8 4m16 0l-8 4m8-4v10l-8 4m0-10L4 7m8 4v10M4 7v10l8 4" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
          </div>
          <div>
            <div className="font-semibold text-slate-100 leading-tight">Traffic Analyzer</div>
            <div className="text-[11px] text-slate-500">SOC Dashboard</div>
          </div>
        </div>
      </div>
      <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
        {NAV.map((n) => (
          <NavButton key={n.to} {...n} />
        ))}
      </nav>
      <div className="px-4 py-3 border-t border-slate-800 text-[11px] text-slate-500">
        Lab-only tool · localhost targets
      </div>
    </aside>
  );
}

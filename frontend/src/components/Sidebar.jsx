import React from 'react';
import { 
  LayoutDashboard, ShieldAlert, ScatterChart as ScatterIcon, 
  GitCommit, Network, FileSearch, Shield, FolderKanban, 
  FileDown, Terminal, LineChart
} from 'lucide-react';

export default function Sidebar({ 
  activeTab, 
  onTabChange, 
  alertCount = 0, 
  caseCount = 0,
  onOpenExport
}) {
  const navItems = [
    { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { id: 'scatter', label: 'Log Explorer', icon: ScatterIcon },
    { 
      id: 'alerts', 
      label: 'Correlated Alerts', 
      icon: ShieldAlert, 
      badge: alertCount, 
      badgeColor: 'bg-[#FEF2F2] text-[#DC2626] border border-[#FECACA]' 
    },
    { id: 'trend', label: 'Activity Trend', icon: LineChart },
    { id: 'timeline', label: 'Investigation Timeline', icon: GitCommit },
    { id: 'traceback', label: 'Traceback', icon: Network },
    { id: 'inspector', label: 'Evidence Inspector', icon: FileSearch },
    { id: 'mitre', label: 'MITRE ATT&CK', icon: Shield },
    { 
      id: 'cases', 
      label: 'Case Management', 
      icon: FolderKanban, 
      badge: caseCount, 
      badgeColor: 'bg-[#F1F5F9] text-[#475569] border border-[#E2E8F0]' 
    },
    { id: 'simulator', label: 'SOC Simulator', icon: Terminal },
    { id: 'reports', label: 'Reports & Export', icon: FileDown, isAction: true },
  ];

  return (
    <aside className="w-60 bg-[#F8FAFC] border-r border-[#E2E8F0] text-[#64748B] flex flex-col shrink-0 min-h-[calc(100vh-53px)] shadow-subtle select-none">
      {/* Navigation Links */}
      <div className="p-3 space-y-1 flex-1">
        <div className="px-3 py-2 text-[10px] font-mono tracking-wider text-[#94A3B8] uppercase font-semibold">
          Forensic Workspaces
        </div>
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => {
                if (item.isAction && onOpenExport) {
                  onOpenExport();
                } else {
                  onTabChange(item.id);
                }
              }}
              className={`w-full flex items-center justify-between px-3 py-2 rounded-lg text-xs font-medium transition-all group ${
                isActive
                  ? 'bg-white text-[#0F172A] font-semibold border-l-2 border-l-[#10B981] shadow-subtle'
                  : 'text-[#64748B] hover:text-[#0F172A] hover:bg-white/80 border-l-2 border-l-transparent'
              }`}
            >
              <div className="flex items-center gap-2.5">
                <Icon className={`w-4 h-4 transition-colors ${
                  isActive ? 'text-[#10B981]' : 'text-[#94A3B8] group-hover:text-[#0F172A]'
                }`} />
                <span>{item.label}</span>
              </div>
              {item.badge !== undefined && item.badge > 0 && (
                <span className={`text-[10px] font-mono px-1.5 py-0.2 rounded font-semibold ${item.badgeColor}`}>
                  {item.badge}
                </span>
              )}
            </button>
          );
        })}
      </div>

      {/* Forensic Guarantee Card */}
      <div className="p-3 m-3 rounded-xl bg-white border border-[#E2E8F0] text-[11px] text-[#64748B] shadow-subtle">
        <div className="flex items-center gap-1.5 text-[#059669] font-semibold mb-1">
          <Shield className="w-3.5 h-3.5 text-[#10B981]" />
          <span>Evidence Integrity</span>
        </div>
        <p className="text-[10px] leading-relaxed text-[#64748B]">
          Raw log records preserved verbatim. Automated correlations generate heuristic hypotheses requiring analyst verification.
        </p>
      </div>
    </aside>
  );
}


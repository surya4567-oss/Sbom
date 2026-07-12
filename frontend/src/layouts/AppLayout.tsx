import { NavLink, Outlet } from 'react-router-dom'
import {
  LayoutDashboard,
  AppWindow,
  GitBranch,
  FileText,
  Shield,
  Upload,
} from 'lucide-react'
import clsx from 'clsx'
import { useState } from 'react'
import { UploadModal } from '../components/UploadModal'

const navItems = [
  { to: '/', icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/applications', icon: AppWindow, label: 'Applications' },
  { to: '/dependency-graph', icon: GitBranch, label: 'Dependency Graph' },
  { to: '/reports', icon: FileText, label: 'Reports' },
]

export function AppLayout() {
  const [uploadOpen, setUploadOpen] = useState(false)

  return (
    <div className="flex min-h-screen">
      <aside className="fixed left-0 top-0 z-30 flex h-full w-64 flex-col border-r border-cyber-700 bg-cyber-900">
        <div className="flex items-center gap-3 border-b border-cyber-700 p-5">
          <Shield className="h-8 w-8 text-cyber-accent" />
          <div>
            <h1 className="text-sm font-bold text-white">SBOM Risk</h1>
            <p className="text-xs text-slate-500">Supply Chain Analyzer</p>
          </div>
        </div>

        <nav className="flex-1 space-y-1 p-4">
          {navItems.map(({ to, icon: Icon, label }) => (
            <NavLink
              key={to}
              to={to}
              end={to === '/'}
              className={({ isActive }) =>
                clsx(
                  'flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-colors',
                  isActive
                    ? 'bg-cyber-accent/10 text-cyber-accent'
                    : 'text-slate-400 hover:bg-cyber-800 hover:text-slate-200',
                )
              }
            >
              <Icon className="h-4 w-4" />
              {label}
            </NavLink>
          ))}
        </nav>

        <div className="border-t border-cyber-700 p-4">
          <button
            onClick={() => setUploadOpen(true)}
            className="flex w-full items-center justify-center gap-2 rounded-lg bg-cyber-accent px-4 py-2.5 text-sm font-medium text-cyber-950 hover:bg-cyber-accent-dim"
          >
            <Upload className="h-4 w-4" />
            Upload SBOM
          </button>
        </div>
      </aside>

      <div className="ml-64 flex flex-1 flex-col">
        <header className="sticky top-0 z-20 border-b border-cyber-700 bg-cyber-950/80 px-8 py-4 backdrop-blur-sm">
          <p className="text-xs uppercase tracking-widest text-slate-500">Software Supply Chain Security</p>
        </header>
        <main className="flex-1 p-8">
          <Outlet />
        </main>
      </div>

      <UploadModal open={uploadOpen} onClose={() => setUploadOpen(false)} />
    </div>
  )
}

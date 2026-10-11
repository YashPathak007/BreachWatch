import {
  Activity,
  AlertTriangle,
  BarChart3,
  Bell,
  BookOpen,
  Check,
  CheckCircle2,
  ChevronRight,
  CircleDot,
  Database,
  FileSearch,
  Filter,
  LogOut,
  Menu,
  RefreshCw,
  Shield,
  SlidersHorizontal,
  X,
} from 'lucide-react';
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { FormEvent, type ReactNode, useEffect, useMemo, useState } from 'react';
import { createRoot } from 'react-dom/client';
import {
  filterAlerts,
  filterEvents,
  formatDate,
  formatTime,
  getErrorMessage,
  initials,
} from './utils';
import './styles.css';

const API = import.meta.env.VITE_API_URL || 'http://localhost:8000/api';

type Role = 'ADMIN' | 'ANALYST' | 'VIEWER';
type Page = 'Dashboard' | 'Events' | 'Alerts' | 'Rules' | 'Audit';
type Severity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
type AlertStatus = 'NEW' | 'ACKNOWLEDGED' | 'INVESTIGATING' | 'RESOLVED' | 'FALSE_POSITIVE';

type User = {
  id: number;
  email: string;
  full_name: string;
  role: Role;
};

type EventItem = {
  id: number;
  timestamp: string;
  source: string;
  event_type: string;
  severity: Severity;
  username?: string | null;
  source_ip?: string | null;
  destination_ip?: string | null;
  hostname?: string | null;
  application?: string | null;
  action?: string | null;
  status?: string | null;
  message: string;
  metadata?: Record<string, unknown>;
  created_at?: string;
};

type AlertItem = {
  id: number;
  title: string;
  severity: Severity;
  status: AlertStatus;
  explanation: string;
  recommended_action: string;
  source_ip?: string | null;
  username?: string | null;
  first_seen: string;
  last_seen: string;
  created_at: string;
  events: EventItem[];
  notes: { id: number; content: string; author: string; created_at: string }[];
  rule: { id: number; key: string; name: string };
  assigned_to?: { id: number; name: string } | null;
};

type DashboardData = {
  total_events: number;
  total_alerts: number;
  open_alerts: number;
  detection_rule_count: number;
  events_over_time: { name: string; value: number }[];
  alerts_by_severity: { name: string; value: number }[];
  alerts_by_status: { name: string; value: number }[];
  top_source_ips: { name: string; value: number }[];
  top_usernames: { name: string; value: number }[];
  recent_alerts: AlertItem[];
  recent_events: EventItem[];
};

type DetectionRule = {
  id: number;
  rule_key: string;
  name: string;
  description: string;
  enabled: boolean;
  severity: Severity;
  config: Record<string, unknown>;
};

type AuditLog = {
  id: number;
  action: string;
  resource_type: string;
  resource_id?: string | null;
  actor: string;
  details: Record<string, unknown>;
  created_at: string;
};

class ApiError extends Error {
  status: number;

  constructor(message: string, status: number) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

async function api<T>(path: string, options: RequestInit = {}): Promise<T> {
  const token = localStorage.getItem('token');
  const headers = new Headers(options.headers);
  headers.set('Accept', 'application/json');
  if (!(options.body instanceof FormData)) headers.set('Content-Type', 'application/json');
  if (token) headers.set('Authorization', `Bearer ${token}`);

  let response: Response;
  try {
    response = await fetch(`${API}${path}`, { ...options, headers });
  } catch (error) {
    throw new ApiError(`Unable to reach the BreachWatch API. ${getErrorMessage(error)}`, 0);
  }

  const contentType = response.headers.get('content-type') || '';
  const payload = contentType.includes('application/json')
    ? await response.json().catch(() => null)
    : await response.text().catch(() => '');

  if (!response.ok) {
    const detail = typeof payload === 'object' && payload !== null && 'detail' in payload
      ? (payload as { detail?: unknown }).detail
      : undefined;
    const message = typeof detail === 'string' ? detail : `Request failed (${response.status})`;
    throw new ApiError(message, response.status);
  }

  return payload as T;
}

function readStoredUser(): User | null {
  try {
    const value = localStorage.getItem('user');
    return value ? (JSON.parse(value) as User) : null;
  } catch {
    localStorage.removeItem('user');
    return null;
  }
}

function isOpenAlert(status: AlertStatus) {
  return ['NEW', 'ACKNOWLEDGED', 'INVESTIGATING'].includes(status);
}

function Login({ onLogin }: { onLogin: (user: User) => void }) {
  const [email, setEmail] = useState('analyst@breachwatch.local');
  const [password, setPassword] = useState('AnalystPass123!');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError('');
    try {
      const data = await api<{ access_token: string; user: User }>('/auth/login', {
        method: 'POST',
        body: JSON.stringify({ email, password }),
      });
      localStorage.setItem('token', data.access_token);
      localStorage.setItem('user', JSON.stringify(data.user));
      onLogin(data.user);
    } catch (error) {
      setError(getErrorMessage(error, 'Unable to sign in. Check the API and try again.'));
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="login-shell">
      <section className="login-art" aria-label="BreachWatch introduction">
        <div className="eyebrow"><Shield size={16} /> BREACHWATCH</div>
        <div className="login-art-copy">
           <p className="kicker">SECURITY WORK FOR YOUR TEAM</p>
           <h1>Know what<br /><em>needs attention.</em></h1>
           <p>BreachWatch turns security events into a focused work queue. Review the evidence, record your decision, and keep the team aligned.</p>
        </div>
        <div className="signal" aria-hidden="true">
          <span /><span /><span /><span /><span /><span /><span />
        </div>
        <div className="login-art-foot"><span className="status-dot" /> Demo environment · synthetic events only</div>
      </section>
      <form className="login-form" onSubmit={submit}>
         <div className="eyebrow">BREACHWATCH WORKSPACE</div>
         <h2>Welcome back</h2>
         <p className="muted">Sign in to review alerts and the evidence behind them. This workspace uses clearly labeled synthetic demo data.</p>
        <div className="form-fields">
          <label>Email<input type="email" value={email} onChange={(event) => setEmail(event.target.value)} autoComplete="username" required /></label>
          <label>Password<input type="password" value={password} onChange={(event) => setPassword(event.target.value)} autoComplete="current-password" required /></label>
        </div>
        {error && <InlineError message={error} />}
        <button className="primary submit-button" disabled={busy} type="submit">
           {busy ? <><RefreshCw className="spin" size={17} /> Signing in...</> : <>Open workspace <ChevronRight size={17} /></>}
        </button>
        <div className="demo-hint">
           <strong>Demo accounts · synthetic data</strong>
          <span>admin@breachwatch.local · AdminPass123!</span>
          <span>analyst@breachwatch.local · AnalystPass123!</span>
          <span>viewer@breachwatch.local · ViewerPass123!</span>
        </div>
      </form>
    </main>
  );
}

function App() {
  const [user, setUser] = useState<User | null>(readStoredUser);
  const [page, setPage] = useState<Page>('Dashboard');
  const [dashboard, setDashboard] = useState<DashboardData | null>(null);
  const [alerts, setAlerts] = useState<AlertItem[]>([]);
  const [events, setEvents] = useState<EventItem[]>([]);
  const [rules, setRules] = useState<DetectionRule[]>([]);
  const [audit, setAudit] = useState<AuditLog[]>([]);
  const [selected, setSelected] = useState<AlertItem | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [connection, setConnection] = useState<'idle' | 'syncing' | 'ready' | 'error'>('idle');

  function logout() {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    setUser(null);
    setSelected(null);
    setPage('Dashboard');
    setConnection('idle');
  }

  async function load(nextPage: Page = page) {
    if (!user) return;
    setLoading(true);
    setConnection('syncing');
    setError('');
    try {
      if (nextPage === 'Dashboard') setDashboard(await api<DashboardData>('/dashboard'));
      if (nextPage === 'Alerts') setAlerts((await api<{ items: AlertItem[] }>('/alerts')).items);
      if (nextPage === 'Events') setEvents((await api<{ items: EventItem[] }>('/events?page_size=100')).items);
      if (nextPage === 'Rules') setRules(await api<DetectionRule[]>('/rules'));
      if (nextPage === 'Audit') setAudit(await api<AuditLog[]>('/audit'));
      setConnection('ready');
    } catch (requestError) {
      if (requestError instanceof ApiError && requestError.status === 401) {
        logout();
        return;
      }
      setConnection('error');
      setError(getErrorMessage(requestError, 'The requested data could not be loaded.'));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    if (user) void load(page);
    // Loading is intentionally tied to the selected workspace page.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [user, page]);

  if (!user) return <Login onLogin={setUser} />;

  const navigation: { name: Page; icon: typeof BarChart3; roles?: Role[] }[] = [
    { name: 'Dashboard', icon: BarChart3 },
    { name: 'Events', icon: Database },
    { name: 'Alerts', icon: Bell },
    { name: 'Rules', icon: SlidersHorizontal },
    { name: 'Audit', icon: BookOpen, roles: ['ADMIN', 'ANALYST'] },
  ];
  const visibleNavigation = navigation.filter((item) => !item.roles || item.roles.includes(user.role));
  const openAlerts = dashboard?.open_alerts ?? alerts.filter((item) => isOpenAlert(item.status)).length;

  function navigate(nextPage: Page) {
    setPage(nextPage);
    setSelected(null);
    setSidebarOpen(false);
  }

  async function refreshSelectedAlert() {
    await load('Alerts');
    if (selected) {
      try {
        setSelected(await api<AlertItem>(`/alerts/${selected.id}`));
      } catch (requestError) {
        setError(getErrorMessage(requestError, 'The alert could not be refreshed.'));
      }
    }
  }

  return (
    <div className="app">
      <div className={`sidebar-backdrop ${sidebarOpen ? 'visible' : ''}`} onClick={() => setSidebarOpen(false)} aria-hidden="true" />
      <aside className={sidebarOpen ? 'open' : ''}>
        <div className="brand"><Shield /><span>BREACH<span>WATCH</span></span></div>
         <div className="workspace"><span className="status-dot" /> DEMO WORKSPACE <small>Synthetic data only</small></div>
        <nav aria-label="Primary navigation">
           <span className="nav-label">WORKSPACE</span>
          {visibleNavigation.map(({ name, icon: Icon }) => (
            <button key={name} className={page === name ? 'active' : ''} onClick={() => navigate(name)} type="button">
              <Icon size={17} />{name}
              {name === 'Alerts' && openAlerts > 0 ? <b>{openAlerts}</b> : null}
            </button>
          ))}
        </nav>
        <div className="aside-bottom">
           <div className="environment-note"><CircleDot size={14} /><span><strong>Data connection ready</strong><small>API status shown above</small></span></div>
          <div className="user-mini"><div className="avatar">{initials(user.full_name)}</div><div><strong>{user.full_name}</strong><small>{user.role} ACCESS</small></div></div>
          <button className="logout" onClick={logout} type="button"><LogOut size={16} /> Sign out</button>
        </div>
      </aside>
      <main className="content">
        <header>
          <button className="mobile-menu" onClick={() => setSidebarOpen(true)} type="button" aria-label="Open navigation"><Menu size={20} /></button>
          <div className="mobile-brand"><Shield size={18} /><strong>BREACHWATCH</strong></div>
          <div className="header-heading"><div className="crumb">SECURITY OPERATIONS / {selected ? 'ALERT DETAIL' : page.toUpperCase()}</div><h1>{selected?.title || page}</h1></div>
          <div className="header-right">
            <span className={`live ${connection}`}><i /> {connection === 'syncing' ? 'REFRESHING DATA' : connection === 'error' ? 'API UNAVAILABLE' : 'API CONNECTED'}</span>
            <div className="avatar">{initials(user.full_name)}</div>
          </div>
        </header>
        {error && <div className="error banner" role="alert"><AlertTriangle size={17} /><span>{error}</span><button onClick={() => setError('')} type="button" aria-label="Dismiss error"><X size={16} /></button></div>}
        {selected ? (
          <AlertDetail alert={selected} user={user} onBack={() => setSelected(null)} onUpdated={refreshSelectedAlert} />
        ) : page === 'Dashboard' ? (
          <Dashboard data={dashboard} loading={loading} error={error} onRetry={() => load('Dashboard')} onGenerate={() => load('Dashboard')} onNavigate={() => navigate('Alerts')} onSelect={setSelected} />
        ) : page === 'Alerts' ? (
          <Alerts items={alerts} loading={loading} error={error} onRetry={() => load('Alerts')} onSelect={setSelected} />
        ) : page === 'Events' ? (
          <Events items={events} loading={loading} error={error} onRetry={() => load('Events')} />
        ) : page === 'Rules' ? (
          <Rules items={rules} loading={loading} error={error} onRetry={() => load('Rules')} user={user} onUpdated={() => load('Rules')} />
        ) : (
          <Audit items={audit} loading={loading} error={error} onRetry={() => load('Audit')} />
        )}
      </main>
    </div>
  );
}

function Dashboard({ data, loading, error, onRetry, onGenerate, onNavigate, onSelect }: { data: DashboardData | null; loading: boolean; error: string; onRetry: () => void; onGenerate: () => Promise<void> | void; onNavigate: () => void; onSelect: (alert: AlertItem) => void }) {
  const [generating, setGenerating] = useState(false);
  const [notice, setNotice] = useState('');

  async function generate() {
    setGenerating(true);
    setNotice('');
    try {
      const result = await api<{ events_created: number; alerts_created: number[] }>('/events/demo', { method: 'POST' });
      const alertSummary = result.alerts_created.length
        ? `${result.alerts_created.length} new ${result.alerts_created.length === 1 ? 'alert' : 'alerts'} created`
        : 'existing detection history updated';
      setNotice(`${result.events_created} synthetic events ingested · ${alertSummary}`);
      await onGenerate();
    } catch (requestError) {
      setNotice(getErrorMessage(requestError, 'Demo sequence could not be generated.'));
    } finally {
      setGenerating(false);
    }
  }

  if (loading && !data) return <PageLoading label="Loading operational telemetry" />;
  if (error && !data) return <PageError message={error} onRetry={onRetry} />;
  if (!data) return <EmptyState icon={Activity} title="No telemetry yet" description="Load the dashboard again or generate the bounded demo sequence to create synthetic activity." action={<button className="primary" onClick={generate} type="button">Generate demo sequence</button>} />;

  const topSource = data.top_source_ips?.[0];
  const topUser = data.top_usernames?.[0];
  const hasEventTrend = data.events_over_time?.some((point) => point.value > 0);
  const hasSeverityData = data.alerts_by_severity?.some((point) => point.value > 0);

  return (
    <div className="page">
      <div className="page-intro dashboard-intro">
        <div><p className="muted">WORKSPACE OVERVIEW · {formatDate(new Date().toISOString(), { dateStyle: 'medium' })}</p><h2>{data.open_alerts ? `${data.open_alerts} ${data.open_alerts === 1 ? 'item needs' : 'items need'} your attention` : 'Nothing needs your attention right now'}</h2><p className="intro-copy">BreachWatch collects security events, checks them against your rules, and gives your team a clear place to investigate. Start with the attention queue below.</p></div>
        <div className="page-actions"><button className="secondary" onClick={generate} disabled={generating} type="button">{generating ? <RefreshCw className="spin" size={16} /> : <Activity size={16} />} {generating ? 'Generating...' : 'Generate demo sequence'}</button><button className="icon-button" onClick={onRetry} disabled={loading} type="button" aria-label="Refresh dashboard" title="Refresh dashboard"><RefreshCw className={loading ? 'spin' : ''} size={17} /></button></div>
      </div>
       {notice && <div className={`notice ${notice.includes('could not') ? 'notice-error' : ''}`} role="status"><CheckCircle2 size={16} /> {notice}</div>}
       <section className={`status-hero ${data.open_alerts ? 'attention' : 'clear'}`} aria-label="Current workspace status"><div className="status-hero-icon">{data.open_alerts ? <AlertTriangle size={21} /> : <CheckCircle2 size={21} />}</div><div><span className="status-kicker">CURRENT STATUS</span><strong>{data.open_alerts ? 'Review the alert queue' : 'Monitoring is clear'}</strong><p>{data.open_alerts ? 'Open alerts are detections that have not reached a final outcome. Open one to review the evidence and choose the next status.' : 'No alerts are currently open. BreachWatch is still collecting the events shown below and will surface a new alert when a rule matches.'}</p></div><button className={data.open_alerts ? 'primary' : 'secondary'} onClick={onNavigate} type="button">{data.open_alerts ? 'Review alerts' : 'View alert history'} <ChevronRight size={16} /></button></section>
      <div className="metrics">
         <Metric label="Events collected" value={data.total_events} icon={Database} tone="cyan" detail="Evidence available to review" />
         <Metric label="Alerts needing attention" value={data.open_alerts} icon={AlertTriangle} tone="red" detail={data.open_alerts ? 'Start with the queue below' : 'No active work'} />
         <Metric label="Alert history" value={data.total_alerts} icon={Bell} tone="amber" detail="All outcomes, including closed" />
         <Metric label="Rules watching" value={data.detection_rule_count} icon={Shield} tone="green" detail="Server-controlled checks" />
      </div>
      <div className="chart-grid">
        <section className="panel chart-panel"><PanelTitle title="Event volume" subtitle="Normalized events by hour" meta={hasEventTrend ? 'LIVE' : 'NO DATA'} />{hasEventTrend ? <ResponsiveContainer width="100%" height={245}><AreaChart data={data.events_over_time}><defs><linearGradient id="eventFill" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="#47d7d1" stopOpacity={0.32} /><stop offset="95%" stopColor="#47d7d1" stopOpacity={0} /></linearGradient></defs><CartesianGrid stroke="#263746" vertical={false} /><XAxis dataKey="name" stroke="#718398" tickLine={false} axisLine={false} /><YAxis stroke="#718398" allowDecimals={false} tickLine={false} axisLine={false} /><Tooltip contentStyle={{ background: '#132331', border: '1px solid #2b4557', borderRadius: 8, color: '#dbe6ef' }} /><Area type="monotone" dataKey="value" stroke="#47d7d1" strokeWidth={2} fill="url(#eventFill)" /></AreaChart></ResponsiveContainer> : <ChartEmpty label="No events have been collected in this workspace." />}</section>
        <section className="panel chart-panel"><PanelTitle title="Alerts by severity" subtitle="Current database distribution" meta={hasSeverityData ? 'DISTRIBUTION' : 'NO DATA'} />{hasSeverityData ? <ResponsiveContainer width="100%" height={245}><BarChart data={data.alerts_by_severity}><CartesianGrid stroke="#263746" vertical={false} /><XAxis dataKey="name" stroke="#718398" tickLine={false} axisLine={false} /><YAxis stroke="#718398" allowDecimals={false} tickLine={false} axisLine={false} /><Tooltip contentStyle={{ background: '#132331', border: '1px solid #2b4557', borderRadius: 8, color: '#dbe6ef' }} /><Bar dataKey="value" fill="#ee765f" radius={[4, 4, 0, 0]} /></BarChart></ResponsiveContainer> : <ChartEmpty label="Detections will appear here as rules match events." />}</section>
      </div>
      <div className="dashboard-grid">
         <section className="panel"><PanelTitle title="What needs attention" subtitle="Open alerts, ordered by latest activity" action={<button className="text-button" onClick={onNavigate} type="button">Open queue <ChevronRight size={14} /></button>} />{data.recent_alerts?.length ? <div className="list">{data.recent_alerts.map((item) => <button className="list-row list-button" key={item.id} onClick={() => onSelect(item)} type="button"><SeverityDot severity={item.severity} /><div className="list-main"><strong>{item.title}</strong><span>{item.explanation}</span></div><div className="list-meta"><StatusBadge status={item.status} /><time>{formatTime(item.last_seen)}</time></div></button>)}</div> : <EmptyState compact icon={Bell} title="The queue is clear" description="No recent alerts need review. Evidence will appear here when a rule matches." />}</section>
         <section className="panel signal-panel"><PanelTitle title="Evidence context" subtitle="Useful context from current data" /><div className="signal-stat"><span><Database size={15} /> Most active source</span><strong>{topSource?.name || 'No source data'}</strong><small>{topSource ? `${topSource.value} collected events` : 'Awaiting collected events'}</small></div><div className="signal-stat"><span><CircleDot size={15} /> Most active user</span><strong>{topUser?.name || 'No user data'}</strong><small>{topUser ? `${topUser.value} collected events` : 'Awaiting collected events'}</small></div><div className="health-row"><CheckCircle2 size={16} /><span><strong>Workspace is connected</strong><small>Events, alerts, and rule results are available from the API</small></span><b>READY</b></div></section>
      </div>
      <section className="panel"><PanelTitle title="Recent activity" subtitle="Latest normalized records" />{data.recent_events?.length ? <div className="activity-list">{data.recent_events.slice(0, 6).map((item) => <div className="activity-row" key={item.id}><span className={`activity-icon ${String(item.severity).toLowerCase()}`}><Activity size={15} /></span><div><strong>{item.event_type}</strong><span>{item.message}</span></div><time>{formatTime(item.timestamp)}</time></div>)}</div> : <EmptyState compact icon={Database} title="No recent events" description="Generate the demo sequence to populate the activity feed." />}</section>
    </div>
  );
}

function Metric({ label, value, icon: Icon, tone, detail }: { label: string; value: number; icon: typeof Database; tone: string; detail: string }) {
  return <div className="metric"><div className={`metric-icon ${tone}`}><Icon size={18} /></div><div><span>{label}</span><strong>{value.toLocaleString()}</strong><small>{detail}</small></div></div>;
}

function PanelTitle({ title, subtitle, meta, action }: { title: string; subtitle?: string; meta?: string; action?: ReactNode }) {
  return <div className="panel-title"><div><h3>{title}</h3>{subtitle && <p>{subtitle}</p>}</div>{action || (meta ? <span className="panel-meta">{meta}</span> : null)}</div>;
}

function SeverityDot({ severity }: { severity?: string }) {
  return <span className={`severity-dot ${String(severity || 'low').toLowerCase()}`} aria-label={`${severity || 'low'} severity`} />;
}

function StatusBadge({ status }: { status: string }) {
  return <span className={`status ${status.toLowerCase()}`}>{status.replace('_', ' ')}</span>;
}

function ChartEmpty({ label }: { label: string }) {
  return <div className="chart-empty"><BarChart3 size={22} /><span>{label}</span></div>;
}

function PageLoading({ label = 'Loading workspace data' }: { label?: string }) {
  return <div className="state-card"><RefreshCw className="spin" size={22} /><strong>{label}</strong><span>Connecting to the telemetry API...</span></div>;
}

function PageError({ message, onRetry }: { message: string; onRetry: () => void }) {
  return <div className="state-card state-error"><AlertTriangle size={24} /><strong>We could not load this view</strong><span>{message}</span><button className="secondary" onClick={onRetry} type="button"><RefreshCw size={15} /> Try again</button></div>;
}

function EmptyState({ icon: Icon, title, description, action, compact = false }: { icon: typeof Activity; title: string; description: string; action?: ReactNode; compact?: boolean }) {
  return <div className={`empty-state ${compact ? 'compact' : ''}`}><span className="empty-icon"><Icon size={compact ? 18 : 23} /></span><strong>{title}</strong><span>{description}</span>{action}</div>;
}

function InlineError({ message }: { message: string }) {
  return <div className="error inline-error" role="alert"><AlertTriangle size={16} /><span>{message}</span></div>;
}

function Alerts({ items, loading, error, onRetry, onSelect }: { items: AlertItem[]; loading: boolean; error: string; onRetry: () => void; onSelect: (item: AlertItem) => void }) {
  const [search, setSearch] = useState('');
  const [severity, setSeverity] = useState('');
  const [status, setStatus] = useState('');
  const visible = useMemo(() => filterAlerts(items, { search, severity, status }), [items, search, severity, status]);
  const hasFilters = Boolean(search || severity || status);

  if (loading && !items.length) return <PageLoading label="Loading alert queue" />;
  if (error && !items.length) return <PageError message={error} onRetry={onRetry} />;

  return <div className="page"><PageIntro eyebrow="DETECTION QUEUE" title="Alerts" description="Prioritize active detections and preserve the evidence behind each decision." action={<button className="icon-button" onClick={onRetry} disabled={loading} type="button" aria-label="Refresh alerts" title="Refresh alerts"><RefreshCw className={loading ? 'spin' : ''} size={17} /></button>} /><Filters search={search} setSearch={setSearch} severity={severity} setSeverity={setSeverity} status={status} setStatus={setStatus} onReset={() => { setSearch(''); setSeverity(''); setStatus(''); }} /><section className="panel table-panel"><div className="table-toolbar"><span>{visible.length} {visible.length === 1 ? 'alert' : 'alerts'} shown</span>{hasFilters && <span className="filter-applied"><Filter size={13} /> Filters active</span>}</div><div className="table-head alert-head"><span>ALERT</span><span>SEVERITY</span><span>STATUS</span><span>SOURCE</span><span>LAST SEEN</span></div>{visible.map((item) => <button className="table-row alert-row" key={item.id} onClick={() => onSelect(item)} type="button"><strong><SeverityDot severity={item.severity} /><span>{item.title}<small>{item.rule.name}</small></span></strong><span className={`pill ${item.severity.toLowerCase()}`}>{item.severity}</span><StatusBadge status={item.status} /><span>{item.source_ip || 'Unknown'}</span><time>{formatDate(item.last_seen)}</time><ChevronRight className="row-chevron" size={16} /></button>)}{!visible.length && <EmptyState compact icon={Bell} title={hasFilters ? 'No alerts match these filters' : 'No alerts in the queue'} description={hasFilters ? 'Try widening the search or clearing a filter.' : 'Detections will appear here when a controlled rule matches.'} action={hasFilters ? <button className="text-button" onClick={() => { setSearch(''); setSeverity(''); setStatus(''); }} type="button">Clear filters</button> : undefined} />}</section></div>;
}

function PageIntro({ eyebrow, title, description, action }: { eyebrow: string; title: string; description: string; action?: ReactNode }) {
  return <div className="page-intro"><div><p className="muted">{eyebrow}</p><h2>{title}</h2><p className="intro-copy">{description}</p></div>{action && <div className="page-actions">{action}</div>}</div>;
}

function Filters({ search, setSearch, severity, setSeverity, status, setStatus, onReset }: { search: string; setSearch: (value: string) => void; severity: string; setSeverity: (value: string) => void; status?: string; setStatus?: (value: string) => void; onReset?: () => void }) {
  const active = Boolean(search || severity || status);
  return <div className="toolbar"><label className="search"><FileSearch size={17} /><span className="sr-only">Search records</span><input placeholder="Search records" value={search} onChange={(event) => setSearch(event.target.value)} /></label><label className="select-wrap"><span className="sr-only">Filter by severity</span><select value={severity} onChange={(event) => setSeverity(event.target.value)}><option value="">All severities</option>{['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((value) => <option key={value}>{value}</option>)}</select></label>{setStatus && <label className="select-wrap"><span className="sr-only">Filter by status</span><select value={status} onChange={(event) => setStatus(event.target.value)}><option value="">All statuses</option>{['NEW', 'ACKNOWLEDGED', 'INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE'].map((value) => <option key={value}>{value.replace('_', ' ')}</option>)}</select></label>}{active && onReset && <button className="text-button clear-button" onClick={onReset} type="button">Clear</button>}</div>;
}

function Events({ items, loading, error, onRetry }: { items: EventItem[]; loading: boolean; error: string; onRetry: () => void }) {
  const [search, setSearch] = useState('');
  const [severity, setSeverity] = useState('');
  const [type, setType] = useState('');
  const types = useMemo(() => [...new Set(items.map((item) => item.event_type))].sort(), [items]);
  const visible = useMemo(() => filterEvents(items, { search, severity, eventType: type }), [items, search, severity, type]);
  const hasFilters = Boolean(search || severity || type);

  if (loading && !items.length) return <PageLoading label="Loading normalized events" />;
  if (error && !items.length) return <PageError message={error} onRetry={onRetry} />;

  return <div className="page"><PageIntro eyebrow="NORMALIZED TELEMETRY" title="Events" description="Search the event stream that powers the detection engine and alert evidence." action={<button className="icon-button" onClick={onRetry} disabled={loading} type="button" aria-label="Refresh events" title="Refresh events"><RefreshCw className={loading ? 'spin' : ''} size={17} /></button>} /><div className="toolbar"><label className="search"><FileSearch size={17} /><span className="sr-only">Search events</span><input placeholder="Search message, user, or source" value={search} onChange={(event) => setSearch(event.target.value)} /></label><label className="select-wrap"><span className="sr-only">Filter by severity</span><select value={severity} onChange={(event) => setSeverity(event.target.value)}><option value="">All severities</option>{['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((value) => <option key={value}>{value}</option>)}</select></label><label className="select-wrap"><span className="sr-only">Filter by event type</span><select value={type} onChange={(event) => setType(event.target.value)}><option value="">All event types</option>{types.map((value) => <option key={value}>{value}</option>)}</select></label>{hasFilters && <button className="text-button clear-button" onClick={() => { setSearch(''); setSeverity(''); setType(''); }} type="button">Clear</button>}</div><section className="panel table-panel"><div className="table-toolbar"><span>{visible.length} of {items.length} events shown</span>{loading && <span className="syncing"><RefreshCw className="spin" size={13} /> Updating</span>}</div><div className="table-head event-head"><span>TIME</span><span>EVENT TYPE</span><span>SOURCE / USER</span><span>SEVERITY</span><span>MESSAGE</span></div>{visible.map((item) => <div className="table-row event-row" key={item.id}><time>{formatDate(item.timestamp)}</time><strong>{item.event_type}<small>{item.source}</small></strong><span>{item.source_ip || '—'}<small>{item.username || 'anonymous'}</small></span><span className={`pill ${item.severity.toLowerCase()}`}>{item.severity}</span><span className="truncate" title={item.message}>{item.message}</span></div>)}{!visible.length && <EmptyState compact icon={Database} title={hasFilters ? 'No events match these filters' : 'No events collected'} description={hasFilters ? 'Try a different search or clear the filters.' : 'Ingest an event or generate the demo sequence to begin.'} action={hasFilters ? <button className="text-button" onClick={() => { setSearch(''); setSeverity(''); setType(''); }} type="button">Clear filters</button> : undefined} />}</section></div>;
}

function AlertDetail({ alert, user, onBack, onUpdated }: { alert: AlertItem; user: User; onBack: () => void; onUpdated: () => Promise<void> }) {
  const [note, setNote] = useState('');
  const [busyAction, setBusyAction] = useState('');
  const [error, setError] = useState('');

  async function change(status: AlertStatus) {
    if (status === alert.status) return;
    setBusyAction(status);
    setError('');
    try {
      await api(`/alerts/${alert.id}/status`, { method: 'PATCH', body: JSON.stringify({ status }) });
      await onUpdated();
    } catch (requestError) {
      setError(getErrorMessage(requestError, 'The alert status could not be updated.'));
    } finally {
      setBusyAction('');
    }
  }

  async function addNote(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!note.trim()) return;
    setBusyAction('note');
    setError('');
    try {
      await api(`/alerts/${alert.id}/notes`, { method: 'POST', body: JSON.stringify({ content: note.trim() }) });
      setNote('');
      await onUpdated();
    } catch (requestError) {
      setError(getErrorMessage(requestError, 'The investigation note could not be saved.'));
    } finally {
      setBusyAction('');
    }
  }

  const canInvestigate = user.role !== 'VIEWER';
  return <div className="page detail"><button className="back" onClick={onBack} type="button">← Back to alerts</button>{error && <InlineError message={error} />}<div className="detail-grid"><section><div className="panel detail-hero"><div className="detail-label"><SeverityDot severity={alert.severity} /> {alert.severity} DETECTION <span className="detail-id">ALERT-{String(alert.id).padStart(4, '0')}</span></div><h2>{alert.title}</h2><p>{alert.explanation}</p><div className="detail-meta"><span><small>RULE</small>{alert.rule.name}</span><span><small>SOURCE</small>{alert.source_ip || 'Unknown'}</span><span><small>USER</small>{alert.username || 'Unknown'}</span><span><small>LAST SEEN</small>{formatDate(alert.last_seen)}</span></div></div><section className="panel"><PanelTitle title="Triggering events" subtitle={`${alert.events.length} correlated ${alert.events.length === 1 ? 'record' : 'records'}`} />{alert.events.length ? <div className="list">{alert.events.map((item) => <div className="list-row" key={item.id}><SeverityDot severity={item.severity} /><div className="list-main"><strong>{item.event_type}</strong><span>{item.message}</span></div><time>{formatTime(item.timestamp)}</time></div>)}</div> : <EmptyState compact icon={Database} title="No linked events" description="The alert has no correlated records." />}</section></section><aside className="detail-side"><section className="panel actions"><div className="panel-title"><h3>Investigation</h3><StatusBadge status={alert.status} /></div><div className="current-status"><small>CURRENT STATUS</small><strong>{alert.status.replace('_', ' ')}</strong><span>Last activity {formatTime(alert.last_seen)}</span></div>{canInvestigate ? <div className="action-stack"><button className="primary full" disabled={Boolean(busyAction)} onClick={() => change('ACKNOWLEDGED')} type="button">{busyAction === 'ACKNOWLEDGED' ? <RefreshCw className="spin" size={15} /> : <Check size={15} />} Acknowledge</button><button className="secondary full" disabled={Boolean(busyAction) || alert.status === 'INVESTIGATING'} onClick={() => change('INVESTIGATING')} type="button">Mark investigating</button><button className="secondary full" disabled={Boolean(busyAction) || alert.status === 'RESOLVED'} onClick={() => change('RESOLVED')} type="button">Resolve alert</button><button className="danger full" disabled={Boolean(busyAction) || alert.status === 'FALSE_POSITIVE'} onClick={() => change('FALSE_POSITIVE')} type="button">Mark false positive</button></div> : <div className="permission-note"><Shield size={15} /> Viewer access is read-only.</div>}<div className="recommendation"><strong>Recommended action</strong><span>{alert.recommended_action}</span></div></section><section className="panel"><PanelTitle title="Investigation notes" subtitle={`${alert.notes.length} ${alert.notes.length === 1 ? 'note' : 'notes'}`} />{alert.notes.length ? <div className="notes">{alert.notes.map((item) => <div className="note" key={item.id}><div><strong>{item.author}</strong><time>{formatDate(item.created_at)}</time></div><p>{item.content}</p></div>)}</div> : <p className="muted note-empty">No analyst notes have been added.</p>}{canInvestigate && <form className="note-form" onSubmit={addNote}><textarea value={note} onChange={(event) => setNote(event.target.value)} placeholder="Document what you found..." maxLength={4000} /><div><span>{note.length}/4000</span><button className="secondary" disabled={!note.trim() || busyAction === 'note'} type="submit">{busyAction === 'note' ? <RefreshCw className="spin" size={14} /> : null} Add note</button></div></form>}</section></aside></div></div>;
}

function Rules({ items, loading, error, onRetry, user, onUpdated }: { items: DetectionRule[]; loading: boolean; error: string; onRetry: () => void; user: User; onUpdated: () => Promise<void> }) {
  const [updating, setUpdating] = useState<number | null>(null);
  const [actionError, setActionError] = useState('');

  async function toggle(rule: DetectionRule) {
    setUpdating(rule.id);
    setActionError('');
    try {
      await api(`/rules/${rule.id}`, { method: 'PATCH', body: JSON.stringify({ enabled: !rule.enabled }) });
      await onUpdated();
    } catch (requestError) {
      setActionError(getErrorMessage(requestError, 'The rule could not be updated.'));
    } finally {
      setUpdating(null);
    }
  }

  if (loading && !items.length) return <PageLoading label="Loading detection rules" />;
  if (error && !items.length) return <PageError message={error} onRetry={onRetry} />;
  return <div className="page"><PageIntro eyebrow="CONTROLLED DETECTION CONFIGURATION" title="Rules in production" description="Server-owned detectors turn normalized events into explainable analyst work." action={<button className="icon-button" onClick={onRetry} disabled={loading} type="button" aria-label="Refresh rules" title="Refresh rules"><RefreshCw className={loading ? 'spin' : ''} size={17} /></button>} />{actionError && <InlineError message={actionError} />}<div className="rule-summary"><span><strong>{items.filter((rule) => rule.enabled).length}</strong> enabled</span><span><strong>{items.length}</strong> total rules</span><span className="permission-note"><Shield size={14} /> {user.role === 'ADMIN' ? 'Admin controls enabled' : 'Admin access required to edit'}</span></div>{items.length ? <div className="rule-list">{items.map((rule) => <section className={`panel rule ${rule.enabled ? '' : 'paused'}`} key={rule.id}><div className="rule-icon"><SlidersHorizontal size={18} /></div><div className="rule-copy"><div className="rule-heading"><h3>{rule.name}</h3><span className={`pill ${rule.severity.toLowerCase()}`}>{rule.severity}</span><span className={`rule-state ${rule.enabled ? 'enabled' : 'disabled'}`}>{rule.enabled ? 'Enabled' : 'Paused'}</span></div><p>{rule.description}</p><code>{JSON.stringify(rule.config, null, 2)}</code></div><label className="switch"><span className="sr-only">{rule.enabled ? 'Disable' : 'Enable'} {rule.name}</span><input type="checkbox" checked={rule.enabled} disabled={user.role !== 'ADMIN' || updating === rule.id} onChange={() => toggle(rule)} /><span /></label></section>)}</div> : <EmptyState icon={SlidersHorizontal} title="No detection rules configured" description="Seed the workspace to load the controlled rule set." />}</div>;
}

function Audit({ items, loading, error, onRetry }: { items: AuditLog[]; loading: boolean; error: string; onRetry: () => void }) {
  if (loading && !items.length) return <PageLoading label="Loading audit trail" />;
  if (error && !items.length) return <PageError message={error} onRetry={onRetry} />;
  return <div className="page"><PageIntro eyebrow="SECURITY-SENSITIVE ACTIONS" title="Audit trail" description="A durable record of authentication, ingestion, detection, and investigation actions." action={<button className="icon-button" onClick={onRetry} disabled={loading} type="button" aria-label="Refresh audit trail" title="Refresh audit trail"><RefreshCw className={loading ? 'spin' : ''} size={17} /></button>} /><section className="panel table-panel"><div className="table-toolbar"><span>{items.length} recent {items.length === 1 ? 'entry' : 'entries'}</span></div><div className="table-head audit-head"><span>TIME</span><span>ACTOR</span><span>ACTION</span><span>RESOURCE</span><span>DETAILS</span></div>{items.map((log) => <div className="table-row audit-row" key={log.id}><time>{formatDate(log.created_at)}</time><strong>{log.actor}</strong><span>{log.action}</span><span>{log.resource_type} #{log.resource_id || '—'}</span><span className="truncate" title={JSON.stringify(log.details)}>{JSON.stringify(log.details)}</span></div>)}{!items.length && <EmptyState compact icon={BookOpen} title="No audit entries yet" description="Security-sensitive actions will be recorded here." />}</section></div>;
}

createRoot(document.getElementById('root')!).render(<App />);

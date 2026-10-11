export type AlertFilterItem = {
  title: string;
  explanation: string;
  severity: string;
  status: string;
};

export type EventFilterItem = {
  message: string;
  event_type: string;
  source_ip?: string | null;
  username?: string | null;
  severity: string;
};

export function filterAlerts<T extends AlertFilterItem>(items: T[], filters: { search: string; severity: string; status: string }): T[] {
  const search = filters.search.trim().toLowerCase();
  return items.filter((item) => {
    const matchesSearch = !search || `${item.title} ${item.explanation}`.toLowerCase().includes(search);
    const matchesSeverity = !filters.severity || item.severity === filters.severity;
    const matchesStatus = !filters.status || item.status === filters.status;
    return matchesSearch && matchesSeverity && matchesStatus;
  });
}

export function filterEvents<T extends EventFilterItem>(items: T[], filters: { search: string; severity: string; eventType: string }): T[] {
  const search = filters.search.trim().toLowerCase();
  return items.filter((item) => {
    const haystack = `${item.message} ${item.event_type} ${item.source_ip || ''} ${item.username || ''}`.toLowerCase();
    const matchesSearch = !search || haystack.includes(search);
    const matchesSeverity = !filters.severity || item.severity === filters.severity;
    const matchesType = !filters.eventType || item.event_type === filters.eventType;
    return matchesSearch && matchesSeverity && matchesType;
  });
}

export function formatDate(value: string | Date | null | undefined, options?: Intl.DateTimeFormatOptions): string {
  if (!value) return '—';
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) return 'Unknown';
  return date.toLocaleString(undefined, options || { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
}

export function formatTime(value: string | Date | null | undefined): string {
  return formatDate(value, { hour: '2-digit', minute: '2-digit' });
}

export function getErrorMessage(error: unknown, fallback = 'Something went wrong.'): string {
  if (typeof error === 'string' && error.trim()) return error;
  if (error instanceof Error && error.message.trim()) return error.message;
  if (typeof error === 'object' && error !== null && 'message' in error) {
    const message = (error as { message?: unknown }).message;
    if (typeof message === 'string' && message.trim()) return message;
  }
  return fallback;
}

export function initials(name: string): string {
  const parts = name.trim().split(/\s+/).filter(Boolean);
  return (parts.length > 1 ? `${parts[0][0]}${parts[parts.length - 1][0]}` : parts[0]?.slice(0, 2) || '?').toUpperCase();
}

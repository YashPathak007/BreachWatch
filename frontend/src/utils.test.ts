import { describe, expect, it } from 'vitest';
import { filterAlerts, filterEvents, formatDate, getErrorMessage, initials } from './utils';

describe('workspace filters', () => {
  it('filters alerts by search, severity, and status together', () => {
    const alerts = [
      { title: 'Brute force', explanation: 'Repeated failed logins', severity: 'HIGH', status: 'NEW' },
      { title: 'Suspicious request', explanation: 'Traversal indicator', severity: 'CRITICAL', status: 'RESOLVED' },
    ];

    expect(filterAlerts(alerts, { search: 'failed', severity: 'HIGH', status: 'NEW' })).toHaveLength(1);
    expect(filterAlerts(alerts, { search: 'failed', severity: 'CRITICAL', status: '' })).toHaveLength(0);
  });

  it('searches event message, type, source, and username', () => {
    const events = [{ message: 'Login failed', event_type: 'authentication', source_ip: '198.51.100.42', username: 'sam.operator', severity: 'MEDIUM' }];
    expect(filterEvents(events, { search: 'sam.operator', severity: '', eventType: '' })).toHaveLength(1);
    expect(filterEvents(events, { search: 'http_request', severity: '', eventType: '' })).toHaveLength(0);
  });
});

describe('presentation helpers', () => {
  it('handles invalid or missing dates without throwing', () => {
    expect(formatDate(undefined)).toBe('—');
    expect(formatDate('not-a-date')).toBe('Unknown');
  });

  it('extracts readable initials and safe error messages', () => {
    expect(initials('Morgan Analyst')).toBe('MA');
    expect(initials('')).toBe('?');
    expect(getErrorMessage(new Error('API unavailable'))).toBe('API unavailable');
    expect(getErrorMessage({ message: 'Bad payload' })).toBe('Bad payload');
  });
});

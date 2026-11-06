import test from 'node:test';
import assert from 'node:assert/strict';
import { settingsTab } from '../src/features/settings/navigation.ts';

test('settings tabs honor validated routes and old notification/metrics bookmarks', () => {
  for (const tab of ['security', 'appearance', 'notifications', 'metrics'])
    assert.equal(settingsTab(new URLSearchParams({ tab })), tab);
  assert.equal(settingsTab(new URLSearchParams({ section: 'notifications' })), 'notifications');
  assert.equal(settingsTab(new URLSearchParams({ section: 'metrics' })), 'metrics');
  assert.equal(settingsTab(new URLSearchParams({ tab: 'unknown', section: 'access' })), 'security');
  assert.equal(settingsTab(new URLSearchParams()), 'security');
});

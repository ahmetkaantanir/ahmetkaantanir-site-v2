import assert from 'node:assert/strict';
import test from 'node:test';
import vm from 'node:vm';
import {readFileSync} from 'node:fs';

const context = vm.createContext({window: {}, URLSearchParams});
vm.runInContext(readFileSync(new URL('../v7.js', import.meta.url), 'utf8'), context);
const api = context.window.labWorkspaceLocalAPI;
const data = {
  events: [{event_id:'one', timestamp:'2026-11-02T10:00:00Z', source:'windows', synthetic:true},
    {event_id:'two', timestamp:'2026-11-02T11:00:00Z', source:'ssh', synthetic:false}],
  cases: [{id:1,status:'investigating',evidence_json:'["one"]'}],
};

test('local case, evidence ID and synthetic filters keep the same scope as private queries', async () => {
  for (const filters of [{status:'investigating'},{event_ids:['one']},{synthetic:true}]) {
    const result = await api('workspace/query', {method:'POST',body:JSON.stringify({filters})}, data);
    assert.equal(result.total, 1);
    assert.equal(result.items[0].event_id, 'one');
  }
});

test('local evidence queries honor chronological ordering before pagination', async () => {
  const result = await api('workspace/query', {method:'POST',body:JSON.stringify({order:'desc',limit:1})}, data);
  assert.equal(result.items[0].event_id,'two');
});

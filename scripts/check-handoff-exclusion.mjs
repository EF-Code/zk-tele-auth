#!/usr/bin/env node
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';

const tracked = execFileSync('git', ['ls-files'], { encoding: 'utf8' })
  .split('\n')
  .filter(Boolean)
  .filter((file) => /\.md$/i.test(file) && /handoff/i.test(file));
assert.deepEqual(tracked, [], `handoff files must remain local-only: ${tracked.join(', ')}`);
console.log('handoff exclusion check: passed');

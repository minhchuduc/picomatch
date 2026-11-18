'use strict';

const assert = require('assert');
const { isMatch, makeRe } = require('..');

/**
 * GHSA-fc5q-39xc-vjpf / CVE-2026-112366: a repeated extglob (`+(...)` or
 * `*(...)`) whose branch holds a bare star nests an unbounded quantifier inside
 * a repeated group, so a short non-matching input blocks the event loop.
 */

const BUDGET_MS = 200;

const timed = (pattern, input, options) => {
  const regex = makeRe(pattern, options);
  const start = process.hrtime.bigint();
  const result = regex.test(input);
  const elapsed = Number(process.hrtime.bigint() - start) / 1e6;
  assert(elapsed < BUDGET_MS, `${pattern} took ${elapsed.toFixed(1)}ms on ${JSON.stringify(input)}`);
  return result;
};

const attacks = [
  ['+(*a)', 'a'.repeat(40) + '!'],
  ['*(*a)', 'a'.repeat(40) + '!'],
  ['+(**a)', 'a'.repeat(40) + '!'],
  ['+(*)x', 'a'.repeat(40) + '!'],
  ['+(*a)b', 'a'.repeat(40) + '!'],
  ['@(+(*a))', 'a'.repeat(40) + '!'],
  ['!(+(*a))', 'a'.repeat(40) + '!'],
  ['+(a*b)', 'aab'.repeat(30) + '/'],
  ['+(a*)', 'a'.repeat(40) + '/'],
  ['+(*a|*a)', 'a'.repeat(40) + '!'],
  ['+(*a|*b)', 'ab'.repeat(30) + '!'],
  ['+(a*|b*)', 'ab'.repeat(30) + '/'],
  ['+(a|*a)', 'a'.repeat(40) + '!'],
  ['+(*a|b)', 'ab'.repeat(30) + '/'],
  ['*(a*|b)', 'a'.repeat(40) + '/'],
  ['+(a*|*b)', 'abc'.repeat(30) + '/'],
  ['+(@(*a)b)', 'ab'.repeat(30) + '/'],
  ['+(!(b))', 'a'.repeat(40) + '/'],
  ['+(a!(b))', 'a'.repeat(40) + '/'],
  ['+(ab|ab)', 'ab'.repeat(30) + '!'],
  ['+(ab|a|b)', 'aab'.repeat(30) + '!'],
  ['+(@(a|aa))', 'a'.repeat(40) + '!'],
  ['+(@(a|b)|a)', 'aab'.repeat(30) + '!'],
  ['+(a|[a])', 'a'.repeat(40) + '!'],
  ['+(?|a|b)', 'a'.repeat(40) + '!'],
  ['+([ab]|a)', 'a'.repeat(40) + '!']
];

describe('repeated extglobs with wildcards (GHSA-fc5q-39xc-vjpf)', () => {
  for (const options of [{}, { dot: true }, { windows: true }, { bash: true }, { capture: true }]) {
    it(`should compile attack patterns to linear-time regexes ${JSON.stringify(options)}`, () => {
      for (const [pattern, input] of attacks) {
        timed(pattern, input, options);
      }
    });
  }

  it('should drop the redundant repetition when one occurrence covers the language', () => {
    assert.strictEqual(makeRe('+(*a)').source, '^(?:(?=.)(?:[^/]*?a))$');
    assert.strictEqual(makeRe('*(*a)').source, '^(?:(?=.)(?:[^/]*?a)?)$');
    assert.strictEqual(makeRe('+(*.js|*.ts)').source, '^(?:(?=.)(?:[^/]*?\\.js|[^/]*?\\.ts))$');
  });

  it('should keep the meaning of rewritten patterns', () => {
    assert(isMatch('aaa', '+(*a)'));
    assert(isMatch('xa', '+(*a)'));
    assert(!isMatch('ab', '+(*a)'));
    assert(isMatch('', '*(*a)', { dot: true }) === isMatch('', '@(|*a)', { dot: true }));
    assert(isMatch('abc', '+(*)c'));
    assert(isMatch('a.js', '+(*.js|*.ts)'));
    assert(isMatch('a.ts.js', '+(*.js|*.ts)'));
    assert(!isMatch('a.jsx', '+(*.js|*.ts)'));
    assert(isMatch('axbab', '+(a*b)'));
    assert(!isMatch('axba', '+(a*b)'));
    assert(!isMatch('a/b', '+(a*b)'));
    assert(isMatch('ax', '*(a*|b)'));
    assert(isMatch('bbax', '*(a*|b)'));
    assert(!isMatch('bbx', '*(a*|b)'));
    assert(isMatch('ba', '+(*a|b)'));
    assert(isMatch('xab', '+(*a|b)'));
    assert(!isMatch('xabx', '+(*a|b)'));
    assert(isMatch('foo', '+(!(f))'));
    assert(isMatch('ba', '+(a|b)'));
    assert(isMatch('aba', '+([ab]|x)'));
    assert(isMatch('ba', '+(a|b)'));
  });

  it('should compile repetitions it cannot rewrite exactly as literals', () => {
    assert.strictEqual(makeRe('+(a!(b))').source, '^(?:\\+\\(a!\\(b\\)\\))$');
    assert.strictEqual(makeRe('+(a*|*b)').source, '^(?:\\+\\(a\\*\\|\\*b\\))$');
    assert.strictEqual(makeRe('+(ab|a|b)').source, '^(?:\\+\\(ab\\|a\\|b\\))$');
    assert(isMatch('+(ab|a|b)', '+(ab|a|b)'));
    assert(!isMatch('aab', '+(ab|a|b)'));
  });

  it('should keep the previous output when the safeguard is disabled', () => {
    assert.strictEqual(
      makeRe('+(*a)', { maxExtglobRecursion: false }).source,
      '^(?:(?=.)(?:[^/]*?a)+)$'
    );
  });
});

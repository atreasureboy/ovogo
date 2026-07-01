import test from 'node:test'
import assert from 'node:assert/strict'
import { applyFilters, formatFilterSummary } from '../dist/src/tools/weaponRadar.js'

const sample = [
  { rank: 1, id: 1, module_name: 'Apache Log4j RCE', attack_logic: 'JNDI injection via log4j', opsec_risk: 4, cve_list: ['CVE-2021-44228'], score: 0.95, score_pct: 95 },
  { rank: 2, id: 2, module_name: 'WordPress File Upload', attack_logic: 'plugin upload bypass', opsec_risk: 2, cve_list: ['CVE-2024-1234'], score: 0.75, score_pct: 75 },
  { rank: 3, id: 3, module_name: 'Shiro Deserialization', attack_logic: 'rememberMe AES key', opsec_risk: 1, cve_list: ['CVE-2016-4437', 'CVE-2020-1957'], score: 0.85, score_pct: 85 },
  { rank: 4, id: 4, module_name: 'Spring Boot Actuator', attack_logic: 'heapdump download', opsec_risk: 3, cve_list: [], score: 0.55, score_pct: 55 },
  { rank: 5, id: 5, module_name: 'Windows SMB RCE', attack_logic: 'eternalblue', opsec_risk: 5, cve_list: ['CVE-2017-0144'], score: 0.92, score_pct: 92 },
]

test('min_score filters out low-relevance results', () => {
  const { results, stats } = applyFilters(sample, { minScore: 70 })
  assert.equal(results.length, 4)
  assert.equal(stats.droppedMinScore, 1)
  assert.equal(results.every((r) => r.score_pct >= 70), true)
})

test('max_opsec filters out noisy PoCs (silent-op mode)', () => {
  const { results, stats } = applyFilters(sample, { maxOpsec: 2 })
  assert.equal(results.length, 2)
  assert.equal(stats.droppedOpsec, 3)
  assert.equal(results.every((r) => r.opsec_risk <= 2), true)
})

test('cve_filter keeps only results matching the CVE whitelist', () => {
  const { results, stats } = applyFilters(sample, { cveFilter: ['CVE-2016-4437', 'CVE-2024-1234'] })
  assert.equal(results.length, 2)
  assert.equal(stats.droppedCve, 3)
  const cves = results.flatMap((r) => r.cve_list)
  assert.ok(cves.includes('CVE-2016-4437'))
  assert.ok(cves.includes('CVE-2024-1234'))
})

test('exclude_keywords removes results whose name/logic matches', () => {
  const { results, stats } = applyFilters(sample, { excludeKeywords: ['Windows', 'SMB'] })
  assert.equal(stats.droppedKeyword, 1)
  assert.equal(results.length, 4)
  assert.equal(results.every((r) => !/windows|smb/i.test(r.module_name)), true)
})

test('topN truncates after filtering (by score desc)', () => {
  const { results, stats } = applyFilters(sample, { topN: 2 })
  assert.equal(results.length, 2)
  assert.equal(stats.truncatedToTopN, 3)
  assert.equal(results[0].score_pct, 95)
  assert.equal(results[1].score_pct, 92)
})

test('filters compose (min_score + max_opsec + cve_filter + top_n)', () => {
  const { results, stats } = applyFilters(sample, {
    minScore: 60,
    maxOpsec: 4,
    cveFilter: ['CVE-2021-44228', 'CVE-2016-4437', 'CVE-2017-0144'],
    topN: 1,
  })
  assert.equal(stats.droppedMinScore, 1)
  assert.equal(stats.droppedOpsec, 1)
  assert.equal(stats.droppedCve, 1)
  assert.equal(stats.truncatedToTopN, 1)
  assert.equal(results.length, 1)
  assert.equal(results[0].id, 1)
})

test('formatFilterSummary includes active filter labels', () => {
  const { stats } = applyFilters(sample, { minScore: 70, maxOpsec: 3, cveFilter: ['CVE-2021-44228'] })
  const s = formatFilterSummary(stats, { minScore: 70, maxOpsec: 3, cveFilter: ['CVE-2021-44228'] })
  assert.match(s, /5→/)
  assert.match(s, /min_score≥70/)
  assert.match(s, /opsec≤3/)
  assert.match(s, /cve∈\{/)
})

test('empty results pass through cleanly', () => {
  const { results, stats } = applyFilters([], { minScore: 50, maxOpsec: 3 })
  assert.equal(results.length, 0)
  assert.equal(stats.before, 0)
  assert.equal(stats.after, 0)
})
// Dolvero trust ledger watchdog. Node 18+. Checks everything that can be checked without trusting dolvero.com:
//   1. every sealed leaf recomputes to its daily root (reviews, replies);
//   2. the previous-review fingerprint chain is unbroken;
//   3. every daily root with on-chain references is found on Base (EAS attestation) and Arweave with the same root;
//   4. roots never change: a local roots.json (if present) must agree with the live feed.
// Exit code 1 on any mismatch. Run it anywhere: `node watchdog.mjs`.
import { createHash } from 'node:crypto';
import { readFileSync, existsSync } from 'node:fs';
const h = (...p) => createHash('sha256').update(Buffer.concat(p)).digest();
const canon = v => Array.isArray(v) ? '[' + v.map(canon).join(',') + ']' : v && typeof v === 'object' ? '{' + Object.keys(v).sort().map(k => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}' : JSON.stringify(v);
const FEED = process.env.FEED || 'https://dolvero.com/trust-feed.json';
const RPCS = ['https://mainnet.base.org', 'https://base-rpc.publicnode.com'];
let bad = 0; const fail = m => { bad++; console.log('FAIL', m); }; const ok = m => console.log('ok  ', m);
const feed = await (await fetch(FEED)).json();
const leafOf = (payloadObj, salt) => h(Buffer.from([0]), Buffer.from('dolvero.leaf.v1'), Buffer.from(salt, 'hex'), h(Buffer.from(canon(payloadObj))));
const climb = (leaf, path) => { let n = leaf; for (const s of path) n = s.side === 'L' ? h(Buffer.from([1]), Buffer.from(s.hash, 'hex'), n) : h(Buffer.from([1]), n, Buffer.from(s.hash, 'hex')); return n.toString('hex'); };
// 1 + 2
let prev = null; const reviews = [...feed.reviews].sort((a, b) => a.id - b.id);
for (const r of reviews) {
  if (r.status === 'published') {
    if (r.prev !== prev) fail(`review ${r.id}: prev fingerprint ${r.prev} expected ${prev}`);
    const sig = r.signature.method === 'passkey' ? { method: 'passkey', credential_sha: r.signature.credential_sha, alg: r.signature.alg, client_data_json: r.signature.client_data_json, authenticator_data: r.signature.authenticator_data, signature: r.signature.signature } : { method: 'session' };
    if (r.leaf) {
      const leaf = leafOf({ v: 1, kind: 'review', review: JSON.parse(r.payload), signature: sig }, r.leaf.salt);
      if (leaf.toString('hex') !== r.leaf.leaf_hash) fail(`review ${r.id}: leaf hash`);
      if (r.leaf.sealed && climb(leaf, r.leaf.path) !== r.leaf.root) fail(`review ${r.id}: Merkle path does not reach root ${r.leaf.day}`); else if (r.leaf.sealed) ok(`review ${r.id} sealed in ${r.leaf.day}`);
    }
    // A reply leaf is its payload; a Dolvero reply signed with a passkey also carries the signature (same fields as a review).
    for (const x of r.replies || []) if (x.leaf) {
      const xs = x.signature || {};
      const body = { v: 1, kind: 'reply', ...JSON.parse(x.payload) };
      if (x.author === 'dolvero' && xs.method === 'passkey') body.signature = { method: 'passkey', credential_sha: xs.credential_sha, alg: xs.alg, client_data_json: xs.client_data_json, authenticator_data: xs.authenticator_data, signature: xs.signature };
      const leaf = leafOf(body, x.leaf.salt);
      if (leaf.toString('hex') !== x.leaf.leaf_hash) fail(`reply ${x.id}: leaf hash`);
      else if (x.leaf.sealed && climb(leaf, x.leaf.path) !== x.leaf.root) fail(`reply ${x.id}: Merkle path does not reach root ${x.leaf.day}`);
      else if (x.leaf.sealed) ok(`reply ${x.id} sealed in ${x.leaf.day}`);
    }
  }
  if (r.leaf) prev = r.leaf.leaf_hash;
}
// 3
const selector = 'a3112a64';
for (const a of feed.anchors || []) {
  if (a.chain && a.chain.arweave) {
    let doc = null; for (const gw of ['https://arweave.net/', 'https://ar-io.net/']) { try { const res = await fetch(gw + a.chain.arweave.id); if (res.ok) { doc = await res.json(); break; } } catch {} }
    if (!doc) console.log('warn', `arweave ${a.day} unreachable`); else if (doc.root !== a.root) fail(`arweave ${a.day}: root ${doc.root}`); else ok(`arweave ${a.day} root matches`);
  }
  if (a.chain && a.chain.base) {
    let res = null; for (const rpc of RPCS) { try { const j = await (await fetch(rpc, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_call', params: [{ to: '0x4200000000000000000000000000000000000021', data: '0x' + selector + a.chain.base.uid.replace(/^0x/, '') }, 'latest'] }) })).json(); if (j.result && j.result.length > 200) { res = j.result; break; } } catch {} }
    if (!res) console.log('warn', `base ${a.day} unreachable`); else { const w = res.slice(2).match(/.{64}/g); const sha = w[12], att = '0x' + w[8].slice(24), schema = '0x' + w[2]; if (sha !== a.root) fail(`base ${a.day}: payloadSha ${sha}`); else if (att.toLowerCase() !== feed.chains.base.attester.toLowerCase() || schema !== feed.chains.base.schema.toLowerCase()) fail(`base ${a.day}: attester/schema`); else ok(`base ${a.day} attestation matches`); }
  }
}
// 4
if (existsSync('roots.json')) { const local = JSON.parse(readFileSync('roots.json', 'utf8')); for (const l of local) { const live = (feed.anchors || []).find(x => x.day === l.day); if (live && live.root !== l.root) fail(`root ${l.day} changed: ${l.root} -> ${live.root}`); } ok(`${local.length} local roots unchanged`); }
console.log(bad ? `${bad} problem(s)` : 'ledger consistent'); process.exit(bad ? 1 : 0);

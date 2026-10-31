// Verify one Dolvero review against the sealed daily root. Node 18+. Usage: node verify.mjs [review id]
import { createHash } from 'node:crypto';
const h = (...p) => createHash('sha256').update(Buffer.concat(p)).digest();
const canon = v => Array.isArray(v) ? '[' + v.map(canon).join(',') + ']'
  : v && typeof v === 'object' ? '{' + Object.keys(v).sort().map(k => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}'
  : JSON.stringify(v);
const feed = await (await fetch('https://dolvero.com/trust-feed.json')).json();
const want = process.argv[2] ? Number(process.argv[2]) : null;
const r = feed.reviews.find(x => x.leaf && x.leaf.sealed && (want === null || x.id === want));
if (!r) { console.log('no sealed review to verify yet'); process.exit(0); }
const payload = canon({ v: 1, kind: 'review', review: JSON.parse(r.payload), signature: r.signature });
let node = h(Buffer.from([0]), Buffer.from('dolvero.leaf.v1'), Buffer.from(r.leaf.salt, 'hex'), h(Buffer.from(payload)));
console.log('review', r.id, 'leaf', node.toString('hex') === r.leaf.leaf_hash ? 'ok' : 'MISMATCH');
for (const s of r.leaf.path) node = s.side === 'L' ? h(Buffer.from([1]), Buffer.from(s.hash, 'hex'), node) : h(Buffer.from([1]), node, Buffer.from(s.hash, 'hex'));
const ok = node.toString('hex') === r.leaf.root;
console.log('root', r.leaf.day, ok ? 'matches' : 'MISMATCH', r.leaf.bitcoin_block ? 'bitcoin #' + r.leaf.bitcoin_block : '');
process.exit(ok ? 0 : 1);

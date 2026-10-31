<?php
/**
 * Dolvero integrity ledger (Michal, 31 Oct 2026): tamper-evident commitments for breaches,
 * later payouts, orders and verified reviews.
 *
 * Every fact becomes a salted leaf; once a day ALL leaves of that UTC day go into ONE Merkle tree
 * of a FIXED size (2^16), padded with keyed dummy leaves at keyed positions, and only the root is
 * timestamped on Bitcoin (OpenTimestamps). The published root therefore says nothing about how many
 * breaches, orders or sales there were; one seal per day, even on an empty day.
 * A single leaf is disclosed (payload + salt + Merkle path) only when a review links to it.
 *
 * Hashing (domain separated, all sha256, hex):
 *   payload_sha = sha256(canonical_json(payload))
 *   leaf        = sha256(0x00 || "dolvero.leaf.v1" || salt(32B) || payload_sha(32B))
 *   node        = sha256(0x01 || left(32B) || right(32B))
 *   dummy_i     = hmac_sha256(day_key, "dummy" || i)        day_key = hmac_sha256(master, "day" || Y-m-d)
 */
declare(strict_types=1);

const IL_DEPTH = 16;               // tree holds 65,536 positions every day, whatever the real count
const IL_KEY_FILE = '/etc/dolvero/integrity.key';

function il_master_key(): string
{
    static $k = null;
    if ($k !== null) { return $k; }
    $hex = trim((string) @file_get_contents(IL_KEY_FILE));
    if (!preg_match('/^[0-9a-f]{64}$/', $hex)) { throw new RuntimeException('integrity key missing'); }
    return $k = hex2bin($hex);
}

function il_day_key(string $day): string
{
    return hash_hmac('sha256', 'day' . $day, il_master_key(), true);
}

/** Canonical JSON: object keys sorted recursively, no whitespace, unescaped unicode and slashes. */
function il_sort($v)
{
    if (!is_array($v)) { return $v; }
    if ($v !== [] && array_keys($v) !== range(0, count($v) - 1)) { ksort($v, SORT_STRING); }
    foreach ($v as $k => $x) { $v[$k] = il_sort($x); }
    return $v;
}

function il_canonical($v): string
{
    return json_encode(il_sort($v), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
}

function il_leaf_hash(string $saltHex, string $payloadShaHex): string
{
    return hash('sha256', "\x00" . 'dolvero.leaf.v1' . hex2bin($saltHex) . hex2bin($payloadShaHex));
}

function il_node(string $l, string $r): string
{
    return hash('sha256', "\x01" . $l . $r, true);
}

function il_ensure_tables(PDO $db): void
{
    $db->exec("CREATE TABLE IF NOT EXISTS integrity_leaves (
        id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        kind VARCHAR(24) NOT NULL,
        ref_table VARCHAR(48) NOT NULL,
        ref_id BIGINT UNSIGNED NOT NULL,
        account_id BIGINT UNSIGNED NULL,
        user_id BIGINT UNSIGNED NULL,
        payload_json MEDIUMTEXT NOT NULL,
        payload_sha CHAR(64) NOT NULL,
        salt CHAR(64) NOT NULL,
        leaf_hash CHAR(64) NOT NULL,
        batch_day DATE NOT NULL,
        leaf_index INT UNSIGNED NULL,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE KEY uq_ref (kind, ref_table, ref_id),
        KEY k_day (batch_day),
        KEY k_account (account_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
    $db->exec("CREATE TABLE IF NOT EXISTS integrity_batches (
        id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        batch_day DATE NOT NULL,
        depth TINYINT UNSIGNED NOT NULL,
        root CHAR(64) NOT NULL,
        ots_proof MEDIUMBLOB NULL,
        ots_status VARCHAR(16) NOT NULL DEFAULT 'pending',
        bitcoin_block INT UNSIGNED NULL,
        sealed_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        upgraded_at DATETIME NULL,
        UNIQUE KEY uq_day (batch_day)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
}

/** Insert one fact as a leaf of today's (UTC) batch. Idempotent per (kind, ref_table, ref_id). */
function il_commit(PDO $db, string $kind, string $refTable, int $refId, array $payload, ?int $accountId = null, ?int $userId = null, ?string $day = null): bool
{
    $payload = ['v' => 1, 'kind' => $kind] + $payload;
    $json = il_canonical($payload);
    $psha = hash('sha256', $json);
    $salt = bin2hex(random_bytes(32));
    /* $day lets the daily stats leaf land in the batch of the day it describes (sealed the next morning). */
    $st = $db->prepare('INSERT IGNORE INTO integrity_leaves (kind, ref_table, ref_id, account_id, user_id, payload_json, payload_sha, salt, leaf_hash, batch_day)
                        VALUES (?,?,?,?,?,?,?,?,?, COALESCE(?, UTC_DATE()))');
    $st->execute([$kind, $refTable, $refId, $accountId, $userId, $json, $psha, $salt, il_leaf_hash($salt, $psha), $day]);
    return $st->rowCount() === 1;
}

/**
 * Keyed placement of real leaves: position = first free slot from hmac(day_key, leaf) mod 2^DEPTH.
 * @return array{0: array<int,string>, 1: array<int,int>} [binary leaves by position, leaf id => position]
 */
function il_layout(string $day, array $real): array
{
    $n = 1 << IL_DEPTH;
    $dk = il_day_key($day);
    $taken = [];
    $pos = [];
    foreach ($real as $id => $leafHex) {
        $p = unpack('N', substr(hash_hmac('sha256', 'pos' . $leafHex, $dk, true), 0, 4))[1] % $n;
        while (isset($taken[$p])) { $p = ($p + 1) % $n; }
        $taken[$p] = hex2bin($leafHex);
        $pos[$id] = $p;
    }
    $leaves = [];
    for ($i = 0; $i < $n; $i++) {
        $leaves[$i] = $taken[$i] ?? hash_hmac('sha256', 'dummy' . $i, $dk, true);
    }
    return [$leaves, $pos];
}

/** @return array{root: string, levels: array<int, array<int,string>>} binary root and all levels (for proofs) */
function il_tree(array $leaves): array
{
    $levels = [$leaves];
    while (count($leaves) > 1) {
        $next = [];
        for ($i = 0, $c = count($leaves); $i < $c; $i += 2) { $next[] = il_node($leaves[$i], $leaves[$i + 1]); }
        $levels[] = $leaves = $next;
    }
    return ['root' => $leaves[0], 'levels' => $levels];
}

/** Merkle path for one position: list of sibling hashes (hex) bottom-up with side markers. */
function il_proof(array $levels, int $pos): array
{
    $path = [];
    for ($lv = 0; $lv < count($levels) - 1; $lv++) {
        $sib = $pos ^ 1;
        $path[] = ['side' => ($pos & 1) ? 'L' : 'R', 'hash' => bin2hex($levels[$lv][$sib])];
        $pos >>= 1;
    }
    return $path;
}

/** Recompute a root from a disclosed leaf (what the public verifier does). */
function il_verify(string $saltHex, string $payloadJson, array $path, string $rootHex): bool
{
    $h = hex2bin(il_leaf_hash($saltHex, hash('sha256', $payloadJson)));
    foreach ($path as $p) {
        $s = hex2bin($p['hash']);
        $h = $p['side'] === 'L' ? il_node($s, $h) : il_node($h, $s);
    }
    return hash_equals($rootHex, bin2hex($h));
}

/** Everything needed to prove one leaf against its sealed, Bitcoin-anchored root. */
function il_disclose(PDO $db, int $leafId): ?array
{
    $st = $db->prepare('SELECT * FROM integrity_leaves WHERE id = ?');
    $st->execute([$leafId]);
    $leaf = $st->fetch(PDO::FETCH_ASSOC);
    if (!$leaf || $leaf['leaf_index'] === null) { return null; }
    $b = $db->prepare('SELECT root, ots_status, bitcoin_block FROM integrity_batches WHERE batch_day = ?');
    $b->execute([$leaf['batch_day']]);
    $batch = $b->fetch(PDO::FETCH_ASSOC);
    if (!$batch) { return null; }
    /* One tree per day per request: the public feed discloses many leaves of the same day. */
    static $memo = [];
    if (!isset($memo[$leaf['batch_day']])) {
        $real = [];
        $q = $db->prepare('SELECT id, leaf_hash FROM integrity_leaves WHERE batch_day = ? ORDER BY id');
        $q->execute([$leaf['batch_day']]);
        foreach ($q as $r) { $real[(int) $r['id']] = $r['leaf_hash']; }
        [$leaves] = il_layout($leaf['batch_day'], $real);
        $memo[$leaf['batch_day']] = il_tree($leaves);
        if (count($memo) > 8) { array_shift($memo); }
    }
    $tree = $memo[$leaf['batch_day']];
    return [
        'day' => $leaf['batch_day'],
        'payload' => $leaf['payload_json'],
        'salt' => $leaf['salt'],
        'leaf' => $leaf['leaf_hash'],
        'path' => il_proof($tree['levels'], (int) $leaf['leaf_index']),
        'root' => $batch['root'],
        'ots_status' => $batch['ots_status'],
        'bitcoin_block' => $batch['bitcoin_block'],
    ];
}

<?php
/**
 * Dolvero verified reviews: the verification side of includes/trust_reviews.php (31 Oct 2026).
 * What a review payload looks like, how a passkey (WebAuthn) assertion is checked, how COSE keys and CBOR are parsed.
 * The write side (eligibility, storage, admin) is not published; nothing here needs it.
 */
declare(strict_types=1);

const TR_RP_ID = 'app.dolvero.com';
const TR_ORIGIN = 'https://app.dolvero.com';

function tr_b64u(string $bin): string { return rtrim(strtr(base64_encode($bin), '+/', '-_'), '='); }

function tr_b64u_dec(string $s): string
{
    $s = strtr($s, '-_', '+/');
    $pad = strlen($s) % 4;
    if ($pad) { $s .= str_repeat('=', 4 - $pad); }
    $r = base64_decode($s, true);
    return $r === false ? '' : $r;
}

function tr_review_payload(array $p): array
{
    return [
        'v' => 1,
        'kind' => 'review',
        'rid' => $p['rid'],
        'rating' => (int) $p['rating'],
        'title' => (string) $p['title'],
        'body' => (string) $p['body'],
        'lang' => (string) $p['lang'],
        'display_name' => (string) $p['display_name'],
        'handle' => (string) $p['handle'],
        'country' => (string) ($p['country'] ?? ''),
        'account_login' => (string) $p['account_login'],
        'product' => (string) $p['product'],
        'purchased_on' => substr((string) $p['purchased_at'], 0, 10),
        'prev' => $p['prev'] === null ? null : (string) $p['prev'],
        'ts' => (string) $p['ts'],
    ];
}

function tr_reply_payload(int $reviewId, string $reviewPayloadSha, string $author, string $authorName, string $body, ?int $supersedes, string $ts): array
{
    return ['v' => 1, 'kind' => 'reply', 'review_id' => $reviewId, 'review_sha' => $reviewPayloadSha, 'author' => $author,
            'author_name' => $authorName, 'body' => $body, 'supersedes' => $supersedes, 'ts' => $ts];
}

function tr_cbor_decode(string $bin): mixed
{
    $pos = 0;
    $v = tr_cbor_item($bin, $pos);
    return $v;
}

function tr_cbor_item(string $b, int &$p): mixed
{
    if ($p >= strlen($b)) { throw new RuntimeException('cbor: truncated'); }
    $ib = ord($b[$p++]);
    $mt = $ib >> 5;
    $ai = $ib & 0x1f;
    $len = $ai;
    if ($ai === 24) { $len = ord($b[$p++]); }
    elseif ($ai === 25) { $len = unpack('n', substr($b, $p, 2))[1]; $p += 2; }
    elseif ($ai === 26) { $len = unpack('N', substr($b, $p, 4))[1]; $p += 4; }
    elseif ($ai === 27) { $len = unpack('J', substr($b, $p, 8))[1]; $p += 8; }
    elseif ($ai > 27) { throw new RuntimeException('cbor: indefinite length unsupported'); }
    switch ($mt) {
        case 0: return $len;
        case 1: return -1 - $len;
        case 2: $s = substr($b, $p, $len); $p += $len; return ['bytes' => $s];
        case 3: $s = substr($b, $p, $len); $p += $len; return $s;
        case 4: $a = []; for ($i = 0; $i < $len; $i++) { $a[] = tr_cbor_item($b, $p); } return $a;
        case 5: $m = []; for ($i = 0; $i < $len; $i++) { $k = tr_cbor_item($b, $p); $v = tr_cbor_item($b, $p); $m[is_array($k) ? bin2hex($k['bytes']) : (string) $k] = $v; } return $m;
        case 7: if ($ai === 20) return false; if ($ai === 21) return true; if ($ai === 22) return null; throw new RuntimeException('cbor: unsupported simple');
    }
    throw new RuntimeException('cbor: bad major type');
}

function tr_cose_to_pem(array $cose, int &$alg): string
{
    $kty = (int) ($cose['1'] ?? 0);
    $alg = (int) ($cose['3'] ?? 0);
    if ($kty === 2) { // EC2
        if ((int) ($cose['-1'] ?? 0) !== 1) { throw new RuntimeException('passkey: only P-256 is accepted'); }
        $x = $cose['-2']['bytes'] ?? ''; $y = $cose['-3']['bytes'] ?? '';
        if (strlen($x) !== 32 || strlen($y) !== 32) { throw new RuntimeException('passkey: bad EC point'); }
        $der = hex2bin('3059301306072a8648ce3d020106082a8648ce3d030107034200') . "\x04" . $x . $y;
    } elseif ($kty === 3) { // RSA
        $n = $cose['-1']['bytes'] ?? ''; $e = $cose['-2']['bytes'] ?? '';
        if ($n === '' || $e === '') { throw new RuntimeException('passkey: bad RSA key'); }
        $int = static function (string $v): string { if (ord($v[0]) & 0x80) { $v = "\x00" . $v; } return "\x02" . tr_der_len(strlen($v)) . $v; };
        $seq = $int($n) . $int($e);
        $rsa = "\x30" . tr_der_len(strlen($seq)) . $seq;
        $bit = "\x03" . tr_der_len(strlen($rsa) + 1) . "\x00" . $rsa;
        $algId = hex2bin('300d06092a864886f70d0101010500');
        $body = $algId . $bit;
        $der = "\x30" . tr_der_len(strlen($body)) . $body;
    } else { throw new RuntimeException('passkey: unsupported key type'); }
    return "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END PUBLIC KEY-----\n";
}

function tr_der_len(int $n): string
{
    if ($n < 0x80) { return chr($n); }
    if ($n < 0x100) { return "\x81" . chr($n); }
    return "\x82" . pack('n', $n);
}

function tr_spki_to_pem(string $der): string
{
    return "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END PUBLIC KEY-----\n";
}

function tr_parse_auth_data(string $ad): array
{
    if (strlen($ad) < 37) { throw new RuntimeException('passkey: short authenticator data'); }
    $out = ['rpIdHash' => substr($ad, 0, 32), 'flags' => ord($ad[32]), 'signCount' => unpack('N', substr($ad, 33, 4))[1], 'credentialId' => null, 'cose' => null, 'aaguid' => null];
    if ($out['flags'] & 0x40) {
        $out['aaguid'] = bin2hex(substr($ad, 37, 16));
        $len = unpack('n', substr($ad, 53, 2))[1];
        $out['credentialId'] = substr($ad, 55, $len);
        $p = 55 + $len;
        $out['cose'] = tr_cbor_item($ad, $p);
    }
    return $out;
}

function tr_check_client_data(string $clientDataJson, string $type, string $challengeB64u): array
{
    $cd = json_decode($clientDataJson, true);
    if (!is_array($cd)) { throw new RuntimeException('passkey: bad clientData'); }
    if (($cd['type'] ?? '') !== $type) { throw new RuntimeException('passkey: wrong ceremony'); }
    if (!hash_equals($challengeB64u, (string) ($cd['challenge'] ?? ''))) { throw new RuntimeException('passkey: challenge mismatch'); }
    if (($cd['origin'] ?? '') !== TR_ORIGIN) { throw new RuntimeException('passkey: origin mismatch'); }
    return $cd;
}

function tr_passkey_assert(PDO $db, int $userId, array $in, string $expectedChallengeB64u): array
{
    $credId = tr_b64u_dec((string) ($in['id'] ?? ''));
    $q = $db->prepare('SELECT * FROM trust_passkeys WHERE credential_sha = ? AND user_id = ?');
    $q->execute([hash('sha256', $credId), $userId]);
    $pk = $q->fetch(PDO::FETCH_ASSOC);
    if (!$pk) { throw new RuntimeException('passkey: unknown credential'); }
    $clientData = tr_b64u_dec((string) ($in['clientDataJSON'] ?? ''));
    tr_check_client_data($clientData, 'webauthn.get', $expectedChallengeB64u);
    $authData = tr_b64u_dec((string) ($in['authenticatorData'] ?? ''));
    $ad = tr_parse_auth_data($authData);
    if (!hash_equals(hash('sha256', TR_RP_ID, true), $ad['rpIdHash'])) { throw new RuntimeException('passkey: rpId mismatch'); }
    if (!($ad['flags'] & 0x01)) { throw new RuntimeException('passkey: user presence not asserted'); }
    $sig = tr_b64u_dec((string) ($in['signature'] ?? ''));
    $signed = $authData . hash('sha256', $clientData, true);
    $key = openssl_pkey_get_public($pk['public_key_pem']);
    if ($key === false || openssl_verify($signed, $sig, $key, OPENSSL_ALGO_SHA256) !== 1) { throw new RuntimeException('passkey: signature invalid'); }
    $db->prepare('UPDATE trust_passkeys SET sign_count = GREATEST(sign_count, ?), last_used_at = UTC_TIMESTAMP() WHERE id = ?')->execute([$ad['signCount'], $pk['id']]);
    return ['passkey' => $pk, 'client_data_json' => $clientData, 'authenticator_data' => $authData, 'signature' => $sig];
}


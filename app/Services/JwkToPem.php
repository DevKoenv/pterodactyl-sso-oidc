<?php

namespace Pterodactyl\BlueprintFramework\Extensions\ssooidc\Services;

use RuntimeException;

/**
 * Converts an RSA JWK (as returned by an OIDC provider's JWKS endpoint)
 * into a PEM-encoded public key usable by openssl/lcobucci-jwt.
 *
 * lcobucci/jwt does not ship a JWK parser, and extensions cannot pull in
 * additional composer dependencies, so this is implemented by hand using
 * plain DER/ASN.1 encoding.
 */
class JwkToPem
{
    public static function fromJwk(array $jwk): string
    {
        if (($jwk['kty'] ?? null) !== 'RSA') {
            throw new RuntimeException('Only RSA JWKs are supported.');
        }

        $modulus = self::base64UrlDecode($jwk['n'] ?? '');
        $exponent = self::base64UrlDecode($jwk['e'] ?? '');

        if ($modulus === '' || $exponent === '') {
            throw new RuntimeException('JWK is missing modulus/exponent.');
        }

        $modulusEncoded = self::encodeInteger($modulus);
        $exponentEncoded = self::encodeInteger($exponent);

        $sequence = self::encodeSequence($modulusEncoded . $exponentEncoded);

        // RSA public key ASN.1 wrapper (RFC 3447 / X.509 SubjectPublicKeyInfo).
        $rsaAlgorithmIdentifier = pack('H*', '300d06092a864886f70d0101010500');
        $bitString = self::encodeBitString($sequence);
        $publicKeyInfo = self::encodeSequence($rsaAlgorithmIdentifier . $bitString);

        $pem = "-----BEGIN PUBLIC KEY-----\n";
        $pem .= chunk_split(base64_encode($publicKeyInfo), 64, "\n");
        $pem .= "-----END PUBLIC KEY-----\n";

        return $pem;
    }

    public static function base64UrlDecode(string $data): string
    {
        $padded = strtr($data, '-_', '+/');
        $padded .= str_repeat('=', (4 - strlen($padded) % 4) % 4);

        return (string) base64_decode($padded);
    }

    private static function encodeLength(int $length): string
    {
        if ($length <= 0x7f) {
            return chr($length);
        }

        $bytes = ltrim(pack('N', $length), "\x00");

        return chr(0x80 | strlen($bytes)) . $bytes;
    }

    private static function encodeInteger(string $bytes): string
    {
        // Ensure the value is interpreted as unsigned/positive by prefixing
        // a null byte when the high bit of the first byte is set.
        if ($bytes !== '' && (ord($bytes[0]) & 0x80)) {
            $bytes = "\x00" . $bytes;
        }

        return "\x02" . self::encodeLength(strlen($bytes)) . $bytes;
    }

    private static function encodeSequence(string $contents): string
    {
        return "\x30" . self::encodeLength(strlen($contents)) . $contents;
    }

    private static function encodeBitString(string $contents): string
    {
        $withUnusedBitsPrefix = "\x00" . $contents;

        return "\x03" . self::encodeLength(strlen($withUnusedBitsPrefix)) . $withUnusedBitsPrefix;
    }
}

<?php

namespace Pterodactyl\BlueprintFramework\Extensions\ssooidc\Services;

use GuzzleHttp\Client;
use Illuminate\Support\Facades\Cache;
use RuntimeException;

/**
 * Fetches and caches an OIDC provider's discovery document and JWKS.
 */
class OidcDiscoveryService
{
    private const CACHE_TTL = 300; // seconds

    public function __construct(private Client $client)
    {
    }

    public function discover(string $issuer): array
    {
        $issuer = rtrim($issuer, '/');
        $cacheKey = 'ssooidc:discovery:' . md5($issuer);

        return Cache::remember($cacheKey, self::CACHE_TTL, function () use ($issuer) {
            $response = $this->client->get($issuer . '/.well-known/openid-configuration', [
                'timeout' => 10,
            ]);

            $document = json_decode((string) $response->getBody(), true);

            if (!is_array($document) || empty($document['authorization_endpoint']) || empty($document['token_endpoint'])) {
                throw new RuntimeException('Invalid OIDC discovery document received from issuer.');
            }

            return $document;
        });
    }

    /**
     * Returns the raw JWKS document (set of signing keys) for the provider.
     */
    public function jwks(string $issuer): array
    {
        $document = $this->discover($issuer);
        $jwksUri = $document['jwks_uri'] ?? null;

        if (!$jwksUri) {
            throw new RuntimeException('OIDC discovery document does not expose a jwks_uri.');
        }

        $cacheKey = 'ssooidc:jwks:' . md5($jwksUri);

        return Cache::remember($cacheKey, self::CACHE_TTL, function () use ($jwksUri) {
            $response = $this->client->get($jwksUri, ['timeout' => 10]);
            $jwks = json_decode((string) $response->getBody(), true);

            if (!is_array($jwks) || empty($jwks['keys'])) {
                throw new RuntimeException('Invalid JWKS document received from issuer.');
            }

            return $jwks;
        });
    }
}

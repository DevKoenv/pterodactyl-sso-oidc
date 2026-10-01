<?php

namespace Pterodactyl\BlueprintFramework\Extensions\sso_oidc\Services;

use GuzzleHttp\Client;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\PermittedFor;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Constraint\LooseValidAt;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;
use Psr\Clock\ClockInterface;
use DateTimeImmutable;
use RuntimeException;

class OidcClientService
{
    public function __construct(
        private Client $client,
        private OidcDiscoveryService $discovery,
    ) {
    }

    public function buildAuthorizationUrl(array $settings, string $redirectUri, string $state, string $nonce, string $codeVerifier, ?string $loginHint = null): string
    {
        $document = $this->discovery->discover($settings['issuer']);

        $methods = $document['code_challenge_methods_supported'] ?? null;

        if (is_array($methods) && !in_array('S256', $methods, true)) {
            throw new RuntimeException(
                'OIDC provider does not support the required PKCE S256 method.'
            );
        }

        $params = [
            'response_type' => 'code',
            'client_id' => $settings['client_id'],
            'redirect_uri' => $redirectUri,
            'scope' => $settings['scopes'] ?: 'openid profile email',
            'state' => $state,
            'nonce' => $nonce,
            // PKCE (RFC 7636). Not strictly required for a confidential
            // client (we hold a client_secret), but it's a cheap extra
            // layer against authorization-code interception/injection, and
            // every provider that matters supports S256.
            'code_challenge' => $this->codeChallenge($codeVerifier),
            'code_challenge_method' => 'S256',
        ];

        // Best-effort hint to the provider about desired auth strength -
        // providers are free to ignore this. Real enforcement happens by
        // checking the returned `amr` claim after login (see
        // OidcCallbackController), not by trusting this request parameter.
        if (!empty($settings['acr_values'])) {
            $params['acr_values'] = $settings['acr_values'];
        }

        // Pre-fills the provider's login form when we already know who's
        // likely logging in (e.g. passed through from a caller that knows
        // the user's email). Optional, purely a UX nicety.
        if ($loginHint) {
            $params['login_hint'] = $loginHint;
        }

        return $document['authorization_endpoint'] . '?' . http_build_query($params);
    }

    /**
     * Exchanges an authorization code for tokens. Returns the decoded
     * token response (id_token, access_token, ...).
     */
    public function exchangeCode(array $settings, string $code, string $redirectUri, string $codeVerifier): array
    {
        $document = $this->discovery->discover($settings['issuer']);

        $response = $this->client->post($document['token_endpoint'], [
            'timeout' => 10,
            'form_params' => [
                'grant_type' => 'authorization_code',
                'code' => $code,
                'redirect_uri' => $redirectUri,
                'client_id' => $settings['client_id'],
                'client_secret' => $settings['client_secret'],
                'code_verifier' => $codeVerifier,
            ],
            'headers' => [
                'Accept' => 'application/json',
            ],
        ]);

        $body = json_decode((string) $response->getBody(), true);

        if (!is_array($body) || empty($body['id_token'])) {
            throw new RuntimeException('Token endpoint did not return an id_token.');
        }

        return $body;
    }

    /**
     * Fetches the provider's userinfo_endpoint as a fallback source for
     * claims that a given provider/configuration doesn't put directly into
     * the id_token. Returns an empty array if the provider has no
     * userinfo_endpoint or the call fails - this is always a best-effort
     * supplement to id_token claims, never a hard requirement.
     */
    public function fetchUserInfo(array $settings, string $accessToken): array
    {
        $document = $this->discovery->discover($settings['issuer']);
        $userinfoEndpoint = $document['userinfo_endpoint'] ?? null;

        if (!$userinfoEndpoint) {
            return [];
        }

        try {
            $response = $this->client->get($userinfoEndpoint, [
                'timeout' => 10,
                'headers' => [
                    'Authorization' => 'Bearer ' . $accessToken,
                    'Accept' => 'application/json',
                ],
            ]);
        } catch (\Throwable) {
            return [];
        }

        $body = json_decode((string) $response->getBody(), true);

        return is_array($body) ? $body : [];
    }

    /**
     * Best-effort revocation of a token we're done with (RFC 7009). We only
     * ever need the id_token's claims - the access_token this extension
     * receives is otherwise unused, so there's no reason to leave it valid
     * at the provider a second longer than necessary. Silently does nothing
     * if the provider has no revocation_endpoint, or the call fails - this
     * is cleanup, never allowed to block or break a login.
     */
    public function revokeToken(array $settings, string $token, string $tokenTypeHint = 'access_token'): void
    {
        try {
            $document = $this->discovery->discover($settings['issuer']);
            $revocationEndpoint = $document['revocation_endpoint'] ?? null;

            if (!$revocationEndpoint) {
                return;
            }

            $this->client->post($revocationEndpoint, [
                'timeout' => 10,
                'form_params' => [
                    'token' => $token,
                    'token_type_hint' => $tokenTypeHint,
                    'client_id' => $settings['client_id'],
                    'client_secret' => $settings['client_secret'],
                ],
                'headers' => [
                    'Accept' => 'application/json',
                ],
            ]);
        } catch (\Throwable) {
            // Best-effort - the token will simply expire on its own later.
        }
    }

    /**
     * Verifies an id_token's signature (via the provider's JWKS), issuer,
     * audience, expiry and nonce. Returns the token's claims as an array.
     */
    public function verifyIdToken(array $settings, string $idToken, string $expectedNonce): array
    {
        $claims = $this->verifySignedToken($settings, $idToken, 'id_token');

        $nonceClaim = $claims['nonce'] ?? null;
        if (!$nonceClaim || !hash_equals((string) $expectedNonce, (string) $nonceClaim)) {
            throw new RuntimeException('id_token nonce mismatch.');
        }

        return $claims;
    }

    /**
     * Verifies a Back-Channel Logout `logout_token` per the OIDC
     * Back-Channel Logout 1.0 spec: same signature/issuer/audience checks
     * as an id_token, but it must carry a `backchannel-logout` event, must
     * NOT carry a `nonce` (that's what tells the two token types apart),
     * and must identify the session via `sub` and/or `sid`. Returns the
     * token's claims as an array.
     */
    public function verifyLogoutToken(array $settings, string $logoutToken): array
    {
        $claims = $this->verifySignedToken($settings, $logoutToken, 'logout_token');

        if (array_key_exists('nonce', $claims)) {
            throw new RuntimeException('logout_token must not contain a nonce claim.');
        }

        $events = $claims['events'] ?? null;
        if (!is_array($events) || !array_key_exists('http://schemas.openid.net/event/backchannel-logout', $events)) {
            throw new RuntimeException('logout_token is missing the backchannel-logout event claim.');
        }

        if (empty($claims['sub']) && empty($claims['sid'])) {
            throw new RuntimeException('logout_token is missing both sub and sid claims.');
        }

        return $claims;
    }

    /**
     * Shared signature/issuer/audience verification for any JWT issued by
     * the configured provider (id_token or logout_token) - both are
     * verified the same way, they just carry different claims afterward.
     */
    private function verifySignedToken(array $settings, string $jwt, string $label): array
    {
        $kid = $this->peekKid($jwt);
        $jwks = $this->discovery->jwks($settings['issuer']);

        $matchingJwk = null;
        foreach ($jwks['keys'] as $jwk) {
            if ($kid === null || ($jwk['kid'] ?? null) === $kid) {
                $matchingJwk = $jwk;
                break;
            }
        }

        if ($matchingJwk === null) {
            throw new RuntimeException("No matching signing key found for {$label} in provider JWKS.");
        }

        $publicKeyPem = JwkToPem::fromJwk($matchingJwk);
        $signer = new Sha256();

        $configuration = Configuration::forAsymmetricSigner(
            $signer,
            InMemory::plainText('unused-for-verification-only'),
            InMemory::plainText($publicKeyPem)
        );

        $document = $this->discovery->discover($settings['issuer']);
        $expectedIssuer = $document['issuer'] ?? rtrim($settings['issuer'], '/');

        $configuration->setValidationConstraints(
            new SignedWith($signer, InMemory::plainText($publicKeyPem)),
            new IssuedBy($expectedIssuer),
            new PermittedFor($settings['client_id']),
            new LooseValidAt($this->systemClock())
        );

        $token = $configuration->parser()->parse($jwt);
        assert($token instanceof \Lcobucci\JWT\UnencryptedToken);

        $constraints = $configuration->validationConstraints();

        try {
            $configuration->validator()->assert($token, ...$constraints);
        } catch (RequiredConstraintsViolated $exception) {
            throw new RuntimeException("{$label} failed validation: " . $exception->getMessage(), 0, $exception);
        }

        return $token->claims()->all();
    }

    /**
     * PKCE (RFC 7636) S256 code_challenge: base64url(sha256(code_verifier)),
     * no padding.
     */
    private function codeChallenge(string $codeVerifier): string
    {
        return rtrim(strtr(base64_encode(hash('sha256', $codeVerifier, true)), '+/', '-_'), '=');
    }

    /**
     * Reads the `kid` header out of a JWT without verifying it, to pick the
     * matching key from the provider's JWKS before real verification.
     * lcobucci/jwt 5.6 dropped Configuration::forUnsecuredSigner(), so this
     * decodes the (unsigned, informational-only) header segment by hand
     * instead of going through the library for this step.
     */
    private function peekKid(string $jwt): ?string
    {
        $segments = explode('.', $jwt);
        if (count($segments) !== 3) {
            throw new RuntimeException('Malformed id_token.');
        }

        $header = json_decode(JwkToPem::base64UrlDecode($segments[0]), true);

        return is_array($header) ? ($header['kid'] ?? null) : null;
    }

    /**
     * lcobucci/jwt's LooseValidAt constraint needs a PSR clock. The
     * `lcobucci/clock` package (SystemClock) is only a dev dependency of
     * lcobucci/jwt, not guaranteed to be installed here, so this
     * implements the tiny `psr/clock` interface directly instead - that
     * package *is* a real (non-dev) dependency of lcobucci/jwt.
     */
    private function systemClock(): ClockInterface
    {
        return new class implements ClockInterface {
            public function now(): DateTimeImmutable
            {
                return new DateTimeImmutable();
            }
        };
    }
}

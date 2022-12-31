<?php

declare(strict_types=1);

namespace Vocweb\Oauth2Tiki\Providers;

use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Provider\ResourceOwnerInterface;
use League\OAuth2\Client\Token\AccessToken;
use Psr\Http\Message\ResponseInterface;
use Vocweb\Oauth2Tiki\Grants\TikiAuthorizationCodeGrant;
use Vocweb\Oauth2Tiki\Grants\TikiRefreshTokenGrant;

class TikiAuthProvider extends AbstractProvider
{
	/**
	 * Default host
	 */
	protected string $host = 'https://api.tiki.vn';

	public function __construct(array $options = [], array $collaborators = [])
	{
		parent::__construct($options, $collaborators);

		$this->getGrantFactory()->setGrant('authorization_code', new TikiAuthorizationCodeGrant());
		$this->getGrantFactory()->setGrant('refresh_token', new TikiRefreshTokenGrant());
		$this->setOptionProvider(new TikiOptionProvider());
	}

	/**
	 * Get authorization url to start the oauth-flow
	 */
	public function getBaseAuthorizationUrl(): string
	{
		return 'https://api.tiki.vn/sc/oauth2/auth';
	}

	public function getBaseAccessTokenUrl(array $params): string
	{
		return 'https://api.tiki.vn/sc/oauth2/token';
	}

	public function getAccessTokenUrl(array $params): string
	{
		if ($params['grant_type'] === 'refresh_token') {
			// Refresh token requires calling a different URL
			return 'https://api.tiki.vn/sc/oauth2/token';
		}

		return 'https://api.tiki.vn/sc/oauth2/token';
	}

	/**
	 * Set authorization parameters
	 */
	protected function getAuthorizationParameters(array $options): array
	{
		$options = parent::getAuthorizationParameters($options);

		$options['client_id'] = $options['client_id'];

		// unset($options['client_id']);

		return $options;
	}

	protected function prepareAccessTokenResponse(array $result): array
	{
		$result['data']['resource_owner_id'] = $result['data']['open_id'];

		return $result['data'];
	}

	/**
	 * @param null|AccessToken $token
	 * @return string[]
	 */
	protected function getAuthorizationHeaders($token = null): array
	{
		return ['Authorization' => 'Bearer ' . $token->getToken()];
	}

	/**
	 * Get provider URl to fetch the user info.
	 */
	public function getResourceOwnerDetailsUrl(AccessToken $token): string
	{
		return 'https://api.tiki.vn/integration/v2/sellers/me';
	}

	/**
	 * Requests and returns the resource owner of given access token.
	 *
	 * @throws IdentityProviderException
	 */
	public function fetchResourceOwnerDetails(AccessToken $token): array
	{
		$url = $this->getResourceOwnerDetailsUrl($token);

		$options = [
			'headers' => $this->getDefaultHeaders(),
			'body' => json_encode(
				[
					'open_id' => $token->getResourceOwnerId(),
					'access_token' => $token->getToken(),
					'fields' => [
						"open_id",
						"union_id",
						"avatar_url",
						"avatar_url_100",
						"avatar_url_200",
						"avatar_large_url",
						"display_name",
						"profile_deep_link",
						"bio_description",
					],
				]
			),
		];

		$request = $this->createRequest(self::METHOD_POST, $url, null, $options);

		return $this->getParsedResponse($request);
	}

	/**
	 * Checks a provider response for errors.
	 *
	 * @throws IdentityProviderException
	 */
	public function checkResponse(ResponseInterface $response, $data): void
	{
		if (isset($data['error']['code']) && $data['error']['code']) {
			throw new IdentityProviderException(
				$data['error']['message'],
				$data['error']['code'],
				$data
			);
		}

		if (isset($data['data']['error_code']) && $data['data']['error_code']) {
			throw new IdentityProviderException(
				$data['data']['description'],
				$data['data']['error_code'],
				$data
			);
		}

		if ($response->getStatusCode() === 401) {
			throw new IdentityProviderException(
				$response->getReasonPhrase(),
				$response->getStatusCode(),
				$data
			);
		}
	}

	public function createResourceOwner(array $response, AccessToken $token): ResourceOwnerInterface
	{
		return new TikiResourceOwner($response);
	}

	public function getDefaultScopes(): array
	{
		return [
			'order',
			'product',
			'inventory',
			'offline',
		];
	}
}

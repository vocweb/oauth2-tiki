<?php

declare(strict_types=1);

namespace Vocweb\Oauth2Tiki\Grants;

use League\OAuth2\Client\Grant\AbstractGrant;

class TikiAuthorizationCodeGrant extends AbstractGrant
{
	protected function getName(): string
	{
		return 'authorization_code';
	}

	protected function getRequiredRequestParameters(): array
	{
		return [
			'code',
		];
	}

	public function prepareRequestParameters(array $defaults, array $options): array
	{
		return [
			'grant_type' => $this->getName(),
			'client_id' => $defaults['client_id'],
			'client_secret' => $defaults['client_secret'],
			'code' => $options['code'],
			'redirect_uri' => $defaults['redirect_uri'],
		];
	}
}

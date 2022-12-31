<?php

namespace Vocweb\Oauth2Tiki\Providers;

use League\OAuth2\Client\OptionProvider\OptionProviderInterface;

class TikiOptionProvider implements OptionProviderInterface
{
	public function getAccessTokenOptions($method, array $params): array
	{
		return [
			'headers' => [
				'Content-Type' => 'application/json',
				'Accept' => 'application/json',
			],
			'body' => json_encode($params),
		];
	}
}

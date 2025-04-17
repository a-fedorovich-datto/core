<?php

namespace tests\OPNsense\Custom;

use PHPUnit\Framework\TestCase;
use GuzzleHttp\Client;

class MyGuiTest extends TestCase
{
    private $client;

    public function setUp(): void
    {
        $this->client = new Client([
            'base_uri' => 'http://localhost:8000',
            'http_errors' => false,
            'cookies' => true,
        ]);
    }

    public function test_ElementExists()
    {
        $response = $this->client->get('/ui/core/dashboard');
        $this->assertEquals(200, $response->getStatusCode());

        $html = (string)$response->getBody();

        $this->assertStringContainsString('class="navbar-toggle', $html, 'Button not found in HTML');
    }
}
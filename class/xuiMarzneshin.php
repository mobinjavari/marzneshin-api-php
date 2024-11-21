<?php

class xuiMarzneshin
{
    private string $host;

    private string $ip;

    private string $auth_token;

    const Method_POST = 'POST';
    const Method_GET = 'GET';
    const Method_PUT = 'PUT';
    const Method_DELETE = 'DELETE';

    const Default_HEADER = 'Content-Type: application/x-www-form-urlencoded';

    public function __construct(
        string $host,
        string|null $ip = null,
        string $username = '',
        string $password = ''
    )
    {
        $this->host = $this->formatServerUrl($host);
        $this->ip = $ip ? $this->formatServerUrl($ip) : '';
        $this->auth_token = $this->authToken($username, $password);
    }

    public function usersStatus() : array
    {
        return $this->sendRequest(
            '/system/stats/users',
            method: self::Method_GET,
            headers: [self::Default_HEADER],
        );
    }

    public function getUser(string $username) : array
    {
        $query = http_build_query([
            'page' => 1,
            'size' => 100,
            'username' => $username,
            'descending' => true,
            'order_by' => 'created_at'
        ]);

        $user = $this->sendRequest(
            '/users',
            method: self::Method_GET,
            query: $query,
            headers: [self::Default_HEADER],
        );

        $user['data'] = $user['data']['items'];

        return $user;
    }

    public function formatServerUrl(string $url): string
    {
        if (filter_var($url, FILTER_VALIDATE_URL)) {
            $addSlashUrl = str_ends_with($url, '/') ? $url : "$url/";

            if (str_starts_with($addSlashUrl, 'api://')) {
                $sslUrl = str_replace('api://', 'ssl://', $addSlashUrl);
                $httpsUrl = str_replace('ssl://', 'https://', $sslUrl);
                $httpUrl = str_replace('https://', 'http://', $httpsUrl);
                $conText = stream_context_create(['ssl' => ['capture_peer_cert' => true]]);
                $stream = stream_socket_client($sslUrl, $errNo, $errMg, 2, STREAM_CLIENT_CONNECT, $conText);

                if (!$stream) {
                    return $httpUrl; // SSL connection failed
                }

                $params = stream_context_get_params($stream);
                $cert = $params['options']['ssl']['peer_certificate'];

                if (!$cert) {
                    return $httpUrl; // No SSL certificate found
                }

                return $httpsUrl; // SSL certificate found
            }

            return $addSlashUrl;
        }

        return '';
    }

    private function authToken(string $username, string $password): string
    {
        $data = http_build_query([
            'username' => $username,
            'password' => $password
        ]);
        $res = $this->sendRequest(
            '/admins/token',
            data: $data,
            method: self::Method_POST,
            headers: [self::Default_HEADER],
            require_auth: false
        );

        return $res['status'] == 200 ? $res['data']['access_token'] ?? '' : '';
    }

    private function sendRequest(
        string $path,
        array|object|string $data = [],
        string $query = '',
        string $method = self::Method_GET,
        array $headers = [],
        bool $require_auth = true,
        string $base_path = 'api'
    ): array {
        if (empty($this->auth_token) && $require_auth)
            return $this->sendResponse(401);

        if (filter_var($this->host, FILTER_VALIDATE_URL)) {
            if ($require_auth)
                $headers[] = 'Authorization: Bearer ' . $this->auth_token;
            $host = empty($this->ip) ? $this->host : $this->ip;
            $options = [
                CURLOPT_URL => $host . "$base_path{$path}",
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_ENCODING => '',
                CURLOPT_MAXREDIRS => 10,
                CURLOPT_TIMEOUT => 10,
                CURLOPT_CONNECTTIMEOUT => 10,
                CURLOPT_SSL_VERIFYPEER => false,
                CURLOPT_SSL_VERIFYHOST => false,
                CURLOPT_FOLLOWLOCATION => true,
                CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
                CURLOPT_HTTPHEADER => $headers,
                CURLOPT_CUSTOMREQUEST => $method
            ];

            if ($method == self::Method_POST || $method == self::Method_PUT) {
                $options[CURLOPT_POSTFIELDS] = $data;
            } else {
                $options[CURLOPT_URL] .= $query ? "?$query" : '';
            }

            $curl = curl_init();
            curl_setopt_array($curl, $options);
            $response = curl_exec($curl);
            $http_code = curl_getinfo($curl, CURLINFO_HTTP_CODE);
            curl_close($curl);
            $data = json_decode($response, true) ?: [];

            return $this->sendResponse($http_code, $data);
        }

        return $this->sendResponse(404);
    }

    private function sendResponse(
        int $http_code,
        array|object|string|null $data = []
    ): array {
        return [
            'status' => $http_code,
            'data' => $data ?: []
        ];
    }
}
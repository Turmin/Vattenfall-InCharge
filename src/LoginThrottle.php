<?php

declare(strict_types=1);

/**
 * Limits failed admin logins per IP address and in total, using a small JSON
 * file outside the web root.
 */
final class LoginThrottle
{
    const WINDOW_SECONDS = 900;
    const MAX_FAILURES_PER_IP = 5;
    const MAX_FAILURES_TOTAL = 30;

    private $file;

    public function __construct(string $file)
    {
        $this->file = $file;
    }

    /**
     * Seconds until a new attempt is allowed for this IP address, 0 when allowed.
     */
    public function secondsUntilAllowed(string $ip, int $now = null): int
    {
        $now = $now ?? time();
        $failures = $this->recentFailures($this->read(), $now);
        $ipKey = $this->ipKey($ip);
        $ipTimes = [];

        foreach ($failures as $failure) {
            if ($failure['ip'] === $ipKey) {
                $ipTimes[] = $failure['time'];
            }
        }

        $wait = 0;

        if (count($ipTimes) >= self::MAX_FAILURES_PER_IP) {
            $oldestCounted = $ipTimes[count($ipTimes) - self::MAX_FAILURES_PER_IP];
            $wait = max($wait, $oldestCounted + self::WINDOW_SECONDS - $now);
        }

        if (count($failures) >= self::MAX_FAILURES_TOTAL) {
            $oldestCounted = $failures[count($failures) - self::MAX_FAILURES_TOTAL]['time'];
            $wait = max($wait, $oldestCounted + self::WINDOW_SECONDS - $now);
        }

        return max(0, $wait);
    }

    public function recordFailure(string $ip, int $now = null)
    {
        $now = $now ?? time();
        $failures = $this->recentFailures($this->read(), $now);
        $failures[] = ['ip' => $this->ipKey($ip), 'time' => $now];
        $this->write($failures);
    }

    public function clear(string $ip)
    {
        $ipKey = $this->ipKey($ip);
        $failures = array_values(array_filter($this->read(), static function (array $failure) use ($ipKey): bool {
            return $failure['ip'] !== $ipKey;
        }));
        $this->write($failures);
    }

    private function ipKey(string $ip): string
    {
        return hash('sha256', $ip);
    }

    private function recentFailures(array $failures, int $now): array
    {
        $cutoff = $now - self::WINDOW_SECONDS;

        return array_values(array_filter($failures, static function (array $failure) use ($cutoff): bool {
            return $failure['time'] > $cutoff;
        }));
    }

    private function read(): array
    {
        if (!is_file($this->file)) {
            return [];
        }

        $data = json_decode((string)@file_get_contents($this->file), true);

        if (!is_array($data)) {
            return [];
        }

        $failures = [];

        foreach ($data as $failure) {
            if (is_array($failure) && is_string($failure['ip'] ?? null) && is_int($failure['time'] ?? null)) {
                $failures[] = ['ip' => $failure['ip'], 'time' => $failure['time']];
            }
        }

        return $failures;
    }

    private function write(array $failures)
    {
        @file_put_contents($this->file, json_encode($failures), LOCK_EX);
    }
}

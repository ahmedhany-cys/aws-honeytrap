-- Credential pairs (masked) attempted from many IPs: shared wordlists / botnets.
SELECT username,
       password_masked,
       credential_fingerprint,
       count(DISTINCT src_ip) AS distinct_ips,
       count(*)               AS attempts
FROM events
WHERE origin = 'live'
  AND category = 'authentication'
  AND dt >= date_format(current_date - interval '30' day, '%Y-%m-%d')
GROUP BY username, password_masked, credential_fingerprint
HAVING count(DISTINCT src_ip) >= 5
ORDER BY distinct_ips DESC
LIMIT 50;

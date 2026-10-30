-- Top source IPs by event volume over the last 7 days (live telemetry only).
SELECT src_ip,
       count(*)                                    AS events,
       count(DISTINCT session_id)                  AS sessions,
       count_if(event_type = 'cowrie.login.failed') AS failed_logins,
       count_if(event_type = 'cowrie.command.input') AS commands
FROM events
WHERE origin = 'live'
  AND dt >= date_format(current_date - interval '7' day, '%Y-%m-%d')
GROUP BY src_ip
ORDER BY events DESC
LIMIT 25;

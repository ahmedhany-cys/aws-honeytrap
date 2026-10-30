-- High and Critical alerts in the last 3 days.
SELECT first_seen, severity, rule_id, rule_name, src_ip, summary
FROM alerts
WHERE origin = 'live'
  AND severity IN ('High', 'Critical')
  AND dt >= date_format(current_date - interval '3' day, '%Y-%m-%d')
ORDER BY first_seen DESC;

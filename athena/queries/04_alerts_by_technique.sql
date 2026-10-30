-- ATT&CK technique frequency across alerts.
SELECT t.technique_id, t.name, count(*) AS alerts, count(DISTINCT a.src_ip) AS source_ips
FROM alerts a
CROSS JOIN UNNEST(a.techniques) AS u(t)
WHERE a.origin = 'live'
GROUP BY t.technique_id, t.name
ORDER BY alerts DESC;

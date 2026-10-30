-- Every URL and payload hash seen in download attempts (IOC extraction).
SELECT dt, src_ip, session_id, event_type, url, file_sha256, command
FROM events
WHERE origin = 'live'
  AND (category = 'download'
       OR regexp_like(coalesce(command, ''), '(wget|curl|tftp|ftpget)\s'))
ORDER BY timestamp DESC
LIMIT 200;

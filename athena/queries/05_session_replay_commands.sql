-- Full command sequence for one session (replace the session id).
SELECT timestamp, src_ip, command
FROM events
WHERE event_type = 'cowrie.command.input'
  AND session_id = 'REPLACE_SESSION_ID'
ORDER BY timestamp;

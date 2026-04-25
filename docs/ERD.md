# ER Diagram (Text)

- users (id, name, email, password_hash, role, created_at)
- bus_pass (pass_id, user_id, route, pass_type, status, fraud_score, fraud_flag, validity, photo_path, timestamps...)
- renewals (id, pass_id, user_id, status, timestamps)
- audit_logs (id, actor_email, action, pass_id, details, created_at)

Relationships:
users 1..* bus_pass, bus_pass 1..* renewals, bus_pass 1..* audit_logs.

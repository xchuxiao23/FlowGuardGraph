INSERT INTO analytics_service.user_statistics
SELECT name, age, gender FROM internal_db.user_profile;

INSERT INTO risk_engine.payment_risk_features
SELECT order_id, amount, device_id FROM internal_db.payment_info;

INSERT INTO recommendation_service.behavior_features
SELECT product_id, device_id FROM internal_db.device_log;

INSERT INTO external_crm.customer_contact
SELECT email, phone FROM internal_db.customer_service;

INSERT INTO external_partner.sensitive_export
SELECT id_card, bank_card, medical_record FROM internal_db.user_profile;

INSERT INTO unknown_external.credential_leak
SELECT password, private_key, auth_token FROM internal_db.audit_log;

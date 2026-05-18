INSERT INTO analytics_service.user_statistics
SELECT name, age FROM internal_db.user_profile;

INSERT INTO analytics_service.order_metrics
SELECT order_id, amount FROM internal_db.order_info;

INSERT INTO external_crm.customer_email
SELECT email FROM internal_db.user_profile;

INSERT INTO external_partner.sensitive_export
SELECT id_card, phone FROM internal_db.user_profile;

INSERT INTO unknown_external.credential_dump
SELECT password FROM internal_db.user_profile;

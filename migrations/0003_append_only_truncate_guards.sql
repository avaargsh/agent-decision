-- Version 3: TRUNCATE does not invoke row-level DELETE triggers.
-- Protect immutable DecisionRecord and Outbox tables with statement guards.
-- Do not rewrite released v1/v2 source bytes or their checksums.
CREATE TRIGGER decision_records_no_truncate
BEFORE TRUNCATE ON decision_records
FOR EACH STATEMENT EXECUTE FUNCTION reject_decision_record_mutation();

CREATE TRIGGER outbox_events_no_truncate
BEFORE TRUNCATE ON outbox_events
FOR EACH STATEMENT EXECUTE FUNCTION reject_decision_outbox_delete();

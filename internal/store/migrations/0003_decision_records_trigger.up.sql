CREATE TRIGGER decision_records_append_only
BEFORE UPDATE OR DELETE ON decision_records
FOR EACH ROW EXECUTE FUNCTION reject_decision_record_mutation();

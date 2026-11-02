CREATE TRIGGER outbox_event_identity_immutable
BEFORE UPDATE ON outbox_events
FOR EACH ROW EXECUTE FUNCTION reject_outbox_event_identity_mutation();

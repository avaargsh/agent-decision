CREATE FUNCTION reject_decision_record_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'decision_records are append-only';
END;
$$;

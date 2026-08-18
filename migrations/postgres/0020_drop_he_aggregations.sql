-- Drop the homomorphic-aggregation table.
--
-- The HE subsystem was removed, and with it migration 0010 that created this
-- table. Deleting a forward migration does not undo one that already ran, so
-- every database provisioned before the removal still carries `he_aggregations`
-- with nothing in the codebase that reads or writes it — and, being Paillier
-- ciphertext keyed by cohort, nothing that could interpret it either.
--
-- A fresh database never had the table, hence IF EXISTS.
DROP TABLE IF EXISTS he_aggregations;

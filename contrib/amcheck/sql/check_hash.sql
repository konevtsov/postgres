-- Test of hash index bulk load
CREATE TABLE hash_check (a int4, b text);
INSERT INTO hash_check
	SELECT g, md5(g::text)
	FROM generate_series(1, 10000) g;
CREATE INDEX hash_check_idx ON hash_check USING hash (a);
SELECT hash_index_check('hash_check_idx');

-- Test hash index inserts
CREATE TABLE hash_check_insert (a int4);
CREATE INDEX hash_check_insert_idx ON hash_check_insert USING hash (a);
INSERT INTO hash_check_insert
	SELECT g
	FROM generate_series(1, 10000) g;
SELECT hash_index_check('hash_check_insert_idx');

-- Test overflow page chains
CREATE TABLE hash_check_overflow (a int4);
INSERT INTO hash_check_overflow
	SELECT 1
	FROM generate_series(1, 5000) g;
CREATE INDEX hash_check_overflow_idx
	ON hash_check_overflow USING hash (a) WITH (fillfactor = 10);
SELECT hash_index_check('hash_check_overflow_idx');

-- Test an empty hash index
CREATE TABLE hash_check_empty (a int4);
CREATE INDEX hash_check_empty_idx ON hash_check_empty USING hash (a);
SELECT hash_index_check('hash_check_empty_idx');

-- Verify that EXECUTE permission is required
CREATE ROLE regress_hash_check_role;
SET ROLE regress_hash_check_role;
SELECT hash_index_check('hash_check_idx');
RESET ROLE;

-- Test invalid relation targets
SELECT hash_index_check('hash_check');
SELECT hash_index_check(17);

BEGIN;
CREATE TABLE hash_check_partitioned (a int4) PARTITION BY RANGE (a);
CREATE INDEX hash_check_partitioned_idx
	ON hash_check_partitioned USING hash (a);
SELECT hash_index_check('hash_check_partitioned_idx');
ROLLBACK;

-- Test wrong index access method
CREATE INDEX hash_check_btree_idx ON hash_check USING btree (a);
SELECT hash_index_check('hash_check_btree_idx');

-- cleanup
DROP TABLE hash_check;
DROP TABLE hash_check_insert;
DROP TABLE hash_check_overflow;
DROP TABLE hash_check_empty;
DROP ROLE regress_hash_check_role;

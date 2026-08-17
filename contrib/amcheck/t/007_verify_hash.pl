# Copyright (c) 2026, PostgreSQL Global Development Group

# Tests for hash index verification in amcheck.
use strict;
use warnings FATAL => 'all';

use PostgreSQL::Test::Cluster;
use PostgreSQL::Test::Utils;

use Test::More;

my $node;
my $blksize;

#
# Test set-up
#
$node = PostgreSQL::Test::Cluster->new('hash_test');
$node->init(no_data_checksums => 1);
$node->append_conf('postgresql.conf', 'autovacuum = off');
$node->start;
$blksize = int($node->safe_psql('postgres', 'SHOW block_size;'));
$node->safe_psql('postgres', q(CREATE EXTENSION amcheck));

valid_hash_index_test();
invalid_hash_page_id_test();

$node->stop;
done_testing();

sub valid_hash_index_test
{
	my ($result, $stdout, $stderr);

	$node->safe_psql(
		'postgres', q(
		CREATE TABLE hash_check_bulk(a int4, b text);
		INSERT INTO hash_check_bulk
			SELECT g, md5(g::text)
			FROM generate_series(1, 10000) g;
		CREATE INDEX hash_check_bulk_idx ON hash_check_bulk USING hash (a);
	));

	($result, $stdout, $stderr) =
	  $node->psql('postgres', q(SELECT hash_index_check('hash_check_bulk_idx')));
	is($result, '0', 'hash_index_check passes for bulk-loaded hash index');

	$node->safe_psql(
		'postgres', q(
		CREATE TABLE hash_check_insert(a int4);
		CREATE INDEX hash_check_insert_idx ON hash_check_insert USING hash (a);
		INSERT INTO hash_check_insert
			SELECT g
			FROM generate_series(1, 10000) g;
	));

	($result, $stdout, $stderr) =
	  $node->psql('postgres',
		q(SELECT hash_index_check('hash_check_insert_idx')));
	is($result, '0', 'hash_index_check passes for insert-built hash index');

	$node->safe_psql(
		'postgres', q(
		CREATE TABLE hash_check_overflow(a int4);
		INSERT INTO hash_check_overflow
			SELECT 1
			FROM generate_series(1, 5000) g;
		CREATE INDEX hash_check_overflow_idx
			ON hash_check_overflow USING hash (a) WITH (fillfactor = 10);
	));

	($result, $stdout, $stderr) =
	  $node->psql('postgres',
		q(SELECT hash_index_check('hash_check_overflow_idx')));
	is($result, '0', 'hash_index_check passes for hash index with overflow pages');

	return;
}

sub invalid_hash_page_id_test
{
	my $relname = 'hash_check_corrupt';
	my $indexname = 'hash_check_corrupt_idx';

	$node->safe_psql(
		'postgres', qq(
		CREATE TABLE $relname(a int4);
		INSERT INTO $relname
			SELECT g
			FROM generate_series(1, 1000) g;
		CREATE INDEX $indexname ON $relname USING hash (a);
	));

	my $relpath = relation_filepath($indexname);

	$node->stop;

	# Block 1 is bucket 0 in a freshly-created hash index.  Corrupt the
	# hash-specific page ID stored as the final uint16 in the page's special
	# space.
	overwrite_hash_page_id($relpath, 1, 0);

	$node->start;

	my ($result, $stdout, $stderr) =
	  $node->psql('postgres', qq(SELECT hash_index_check('$indexname')));
	isnt($result, '0', 'hash_index_check fails for corrupted hash page id');
	like(
		$stderr,
		qr/index "$indexname" block 1 has invalid hash page id/,
		'hash_index_check reports corrupted hash page id');

	return;
}

# Returns the filesystem path for the named relation.
sub relation_filepath
{
	my ($relname) = @_;

	my $pgdata = $node->data_dir;
	my $rel = $node->safe_psql('postgres',
		qq(SELECT pg_relation_filepath('$relname')));
	die "path not found for relation $relname" unless defined $rel;
	return "$pgdata/$rel";
}

# Overwrite hasho_page_id in the hash page opaque area for block blkno.
sub overwrite_hash_page_id
{
	my ($filename, $blkno, $page_id) = @_;

	my $fh;
	open($fh, '+<', $filename) or BAIL_OUT("open failed: $!");
	binmode $fh;

	my $offset = ($blkno + 1) * $blksize - 2;

	sysseek($fh, $offset, 0) or BAIL_OUT("seek failed: $!");
	syswrite($fh, pack('S', $page_id)) or BAIL_OUT("write failed: $!");

	close($fh) or BAIL_OUT("close failed: $!");

	return;
}

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

invalid_hash_page_id_test();
invalid_overflow_link_test();
zero_bitmap_page_test();
invalid_bitmap_bit_test();
invalid_metapage_field_test();
invalid_metapage_header_test();
invalid_bitmap_header_test();

$node->stop;
done_testing();

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

sub invalid_overflow_link_test
{
	my ($indexname, $relpath) = create_overflow_index('bad_link');
	my $blkno = find_hash_page($relpath, 0x01);

	$node->stop;
	overwrite_uint32($relpath, $blkno, $blksize - 12, $blkno);
	$node->start;

	my ($result, $stdout, $stderr) =
	  $node->psql('postgres', qq(SELECT hash_index_check('$indexname')));
	isnt($result, '0', 'hash_index_check fails for a cyclic overflow link');
	like($stderr, qr/chain links to block $blkno more than once/,
		'hash_index_check reports a cyclic overflow link');
}

sub zero_bitmap_page_test
{
	my ($indexname, $relpath) = create_overflow_index('zero_bitmap');
	my $blkno = find_hash_page($relpath, 0x04);

	$node->stop;
	overwrite_block($relpath, $blkno, "\0" x $blksize);
	$node->start;

	my ($result, $stdout, $stderr) =
	  $node->psql('postgres', qq(SELECT hash_index_check('$indexname')));
	isnt($result, '0', 'hash_index_check fails for a zero bitmap page');
	like($stderr, qr/unexpected zero page at block $blkno/,
		'hash_index_check reports a zero bitmap page');
}

sub invalid_bitmap_bit_test
{
	my ($indexname, $relpath) = create_overflow_index('bad_bitmap');
	my $blkno = find_hash_page($relpath, 0x04);

	$node->stop;
	# Bit zero represents the first bitmap page itself and must be set.
	overwrite_uint32($relpath, $blkno, 24, 0xfffffffe);
	$node->start;

	my ($result, $stdout, $stderr) =
	  $node->psql('postgres', qq(SELECT hash_index_check('$indexname')));
	isnt($result, '0', 'hash_index_check fails for an incorrect bitmap bit');
	like($stderr, qr/overflow bitmap bit 0 disagrees with block/,
		'hash_index_check reports an incorrect bitmap bit');
}

sub invalid_metapage_field_test
{
	my ($indexname, $relpath) = create_overflow_index('bad_meta');

	$node->stop;
	# hashm_firstfree is at byte 40 in HashMetaPageData, after the
	# 24-byte page header.
	overwrite_uint32($relpath, 0, 64, 0xffffffff);
	$node->start;

	my ($result, $stdout, $stderr) =
	  $node->psql('postgres', qq(SELECT hash_index_check('$indexname')));
	isnt($result, '0', 'hash_index_check fails for invalid metapage metadata');
	like($stderr, qr/inconsistent overflow bitmap metadata/,
		'hash_index_check reports invalid metapage metadata');
}

sub invalid_metapage_header_test
{
	my ($indexname, $relpath) = create_overflow_index('bad_meta_header');

	$node->stop;
	# pd_upper must equal pd_special on a metapage, which has no line
	# pointers or tuple area.
	overwrite_uint16($relpath, 0, 14, $blksize - 32);
	$node->start;

	my ($result, $stdout, $stderr) =
	  $node->psql('postgres', qq(SELECT hash_index_check('$indexname')));
	isnt($result, '0', 'hash_index_check fails for an invalid metapage header');
	like($stderr, qr/has invalid metapage header/,
		'hash_index_check reports an invalid metapage header');
}

sub invalid_bitmap_header_test
{
	my ($indexname, $relpath) = create_overflow_index('bad_bitmap_header');
	my $blkno = find_hash_page($relpath, 0x04);

	$node->stop;
	# Bitmap pages, like metapages, have no tuple area.
	overwrite_uint16($relpath, $blkno, 14, $blksize - 32);
	$node->start;

	my ($result, $stdout, $stderr) =
	  $node->psql('postgres', qq(SELECT hash_index_check('$indexname')));
	isnt($result, '0', 'hash_index_check fails for an invalid bitmap header');
	like($stderr, qr/bitmap page $blkno has invalid page data/,
		'hash_index_check reports an invalid bitmap header');
}

sub create_overflow_index
{
	my ($suffix) = @_;
	my $relname = "hash_check_$suffix";
	my $indexname = "${relname}_idx";

	$node->safe_psql(
		'postgres', qq(
		CREATE TABLE $relname(a int4);
		INSERT INTO $relname SELECT 1 FROM generate_series(1, 5000);
		CREATE INDEX $indexname ON $relname USING hash (a)
			WITH (fillfactor = 10);
	));

	return ($indexname, relation_filepath($indexname));
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

# Return the first block having the requested LH_PAGE_TYPE flag.
sub find_hash_page
{
	my ($filename, $pagetype) = @_;
	my $size = -s $filename;
	my $fh;

	open($fh, '<', $filename) or BAIL_OUT("open failed: $!");
	binmode $fh;
	for (my $blkno = 0; $blkno < $size / $blksize; $blkno++)
	{
		my $data;
		sysseek($fh, ($blkno + 1) * $blksize - 4, 0)
		  or BAIL_OUT("seek failed: $!");
		sysread($fh, $data, 2) == 2 or BAIL_OUT("read failed: $!");
		if ((unpack('S', $data) & 0x0f) == $pagetype)
		{
			close($fh) or BAIL_OUT("close failed: $!");
			return $blkno;
		}
	}
	close($fh) or BAIL_OUT("close failed: $!");
	BAIL_OUT("hash page type $pagetype not found in $filename");
}

sub overwrite_uint32
{
	my ($filename, $blkno, $page_offset, $value) = @_;
	my $fh;

	open($fh, '+<', $filename) or BAIL_OUT("open failed: $!");
	binmode $fh;
	sysseek($fh, $blkno * $blksize + $page_offset, 0)
	  or BAIL_OUT("seek failed: $!");
	syswrite($fh, pack('L', $value)) == 4 or BAIL_OUT("write failed: $!");
	close($fh) or BAIL_OUT("close failed: $!");
}

sub overwrite_uint16
{
	my ($filename, $blkno, $page_offset, $value) = @_;
	my $fh;

	open($fh, '+<', $filename) or BAIL_OUT("open failed: $!");
	binmode $fh;
	sysseek($fh, $blkno * $blksize + $page_offset, 0)
	  or BAIL_OUT("seek failed: $!");
	syswrite($fh, pack('S', $value)) == 2 or BAIL_OUT("write failed: $!");
	close($fh) or BAIL_OUT("close failed: $!");
}

sub overwrite_block
{
	my ($filename, $blkno, $data) = @_;
	my $fh;

	open($fh, '+<', $filename) or BAIL_OUT("open failed: $!");
	binmode $fh;
	sysseek($fh, $blkno * $blksize, 0) or BAIL_OUT("seek failed: $!");
	syswrite($fh, $data) == length($data) or BAIL_OUT("write failed: $!");
	close($fh) or BAIL_OUT("close failed: $!");
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

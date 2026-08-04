/*-------------------------------------------------------------------------
 *
 * verify_hash.c
 *		Verifies the integrity of hash indexes based on structural invariants.
 *
 * Hash index verification checks page layout, metapage fields, bucket-to-block
 * mappings, bucket and overflow page links, and tuple hash key ordering and
 * bucket membership.
 *
 * Copyright (c) 2016-2026, PostgreSQL Global Development Group
 *
 * IDENTIFICATION
 *	  contrib/amcheck/verify_hash.c
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include "access/hash.h"
#include "catalog/pg_am.h"
#include "miscadmin.h"
#include "storage/bufmgr.h"
#include "utils/rel.h"
#include "verify_common.h"

typedef struct HashCheckState
{
	Relation	rel;
	HashMetaPageData metap;
	BlockNumber nblocks;
	bool	   *bitmap_pages;
	bool	   *reachable_pages;
	BufferAccessStrategy checkstrategy;
} HashCheckState;

PG_FUNCTION_INFO_V1(hash_index_check);

static void hash_index_check_callback(Relation rel, Relation heaprel,
									  void *callback_state, bool readonly);
static void hash_check_metapage(HashCheckState *state, Page metapage);
static void hash_check_bucket_chain(HashCheckState *state, Bucket bucket);
static void hash_check_page_opaque(HashCheckState *state, Page page,
								   BlockNumber blkno, Bucket bucket,
								   BlockNumber prevblkno, bool primary);
static void hash_check_tuple_page(HashCheckState *state, Page page,
								  BlockNumber blkno, Bucket bucket,
								  bool split_cleanup);
static void hash_check_tuple(HashCheckState *state, Page page,
							 BlockNumber blkno, OffsetNumber offnum,
							 Bucket bucket, bool split_cleanup,
							 Bucket cleanup_bucket, uint32 *lasthashkey,
							 bool *first);
static void hash_check_unreachable_page(HashCheckState *state,
										BlockNumber blkno);
static ItemId PageGetItemIdCareful(HashCheckState *state, Page page,
								   BlockNumber blkno, OffsetNumber offnum);
static const char *hash_page_type_string(uint16 pagetype);

/*
 * hash_index_check(index regclass)
 *
 * Verify integrity of hash index.
 *
 * Acquires ShareLock on heap & index relations.  This prevents concurrent
 * modification while verification walks overflow chains and compares them to
 * the metapage.
 */
Datum
hash_index_check(PG_FUNCTION_ARGS)
{
	Oid			indrelid = PG_GETARG_OID(0);

	amcheck_lock_relation_and_check(indrelid,
									HASH_AM_OID,
									hash_index_check_callback,
									ShareLock,
									NULL);

	PG_RETURN_VOID();
}

static void
hash_index_check_callback(Relation rel, Relation heaprel,
						  void *callback_state, bool readonly)
{
	HashCheckState state;
	Buffer		metabuf;
	Page		metapage;

	state.rel = rel;
	state.nblocks = RelationGetNumberOfBlocks(rel);
	state.checkstrategy = GetAccessStrategy(BAS_BULKREAD);

	if (state.nblocks <= HASH_METAPAGE)
		ereport(ERROR,
				(errcode(ERRCODE_INDEX_CORRUPTED),
				 errmsg("index \"%s\" has no metapage",
						RelationGetRelationName(rel)),
				 errhint("Please REINDEX it.")));

	state.bitmap_pages = palloc0(sizeof(bool) * state.nblocks);
	state.reachable_pages = palloc0(sizeof(bool) * state.nblocks);

	metabuf = _hash_getbuf_with_strategy(rel, HASH_METAPAGE, HASH_READ,
										  LH_META_PAGE, state.checkstrategy);
	metapage = BufferGetPage(metabuf);

	hash_check_metapage(&state, metapage);
	memcpy(&state.metap, HashPageGetMeta(metapage), sizeof(HashMetaPageData));
	state.reachable_pages[HASH_METAPAGE] = true;

	_hash_relbuf(rel, metabuf);

	for (uint32 i = 0; i < state.metap.hashm_nmaps; i++)
	{
		BlockNumber mapblkno = state.metap.hashm_mapp[i];

		if (mapblkno <= HASH_METAPAGE || mapblkno >= state.nblocks)
			ereport(ERROR,
					(errcode(ERRCODE_INDEX_CORRUPTED),
					 errmsg("index \"%s\" has invalid bitmap block number %u in metapage entry %u",
							RelationGetRelationName(rel), mapblkno, i),
					 errhint("Please REINDEX it.")));

		if (state.bitmap_pages[mapblkno])
			ereport(ERROR,
					(errcode(ERRCODE_INDEX_CORRUPTED),
					 errmsg("index \"%s\" has duplicate bitmap block number %u in metapage",
							RelationGetRelationName(rel), mapblkno),
					 errhint("Please REINDEX it.")));

		state.bitmap_pages[mapblkno] = true;
	}

	for (Bucket bucket = 0; bucket <= state.metap.hashm_maxbucket; bucket++)
	{
		CHECK_FOR_INTERRUPTS();
		hash_check_bucket_chain(&state, bucket);
	}

	for (BlockNumber blkno = 1; blkno < state.nblocks; blkno++)
	{
		CHECK_FOR_INTERRUPTS();

		if (!state.reachable_pages[blkno])
			hash_check_unreachable_page(&state, blkno);
	}
}

static void
hash_check_metapage(HashCheckState *state, Page metapage)
{
	HashPageOpaque opaque = HashPageGetOpaque(metapage);
	HashMetaPage metap = HashPageGetMeta(metapage);

	if (opaque->hasho_page_id != HASHO_PAGE_ID ||
		(opaque->hasho_flag & LH_PAGE_TYPE) != LH_META_PAGE ||
		opaque->hasho_prevblkno != InvalidBlockNumber ||
		opaque->hasho_nextblkno != InvalidBlockNumber ||
		opaque->hasho_bucket != InvalidBucket)
		ereport(ERROR,
				(errcode(ERRCODE_INDEX_CORRUPTED),
				 errmsg("index \"%s\" has invalid metapage opaque data",
						RelationGetRelationName(state->rel)),
				 errhint("Please REINDEX it.")));

	if (metap->hashm_maxbucket > metap->hashm_highmask ||
		(uint64) metap->hashm_maxbucket + 1 >= state->nblocks ||
		(metap->hashm_highmask & (metap->hashm_highmask + 1)) != 0 ||
		metap->hashm_lowmask != (metap->hashm_highmask >> 1))
		ereport(ERROR,
				(errcode(ERRCODE_INDEX_CORRUPTED),
				 errmsg("index \"%s\" has inconsistent hash masks in metapage",
						RelationGetRelationName(state->rel)),
				 errhint("Please REINDEX it.")));

	if (metap->hashm_ovflpoint >= HASH_MAX_SPLITPOINTS ||
		metap->hashm_nmaps > HASH_MAX_BITMAPS)
		ereport(ERROR,
				(errcode(ERRCODE_INDEX_CORRUPTED),
				 errmsg("index \"%s\" has out-of-range hash metapage fields",
						RelationGetRelationName(state->rel)),
				 errhint("Please REINDEX it.")));

	if (metap->hashm_ffactor == 0 ||
		metap->hashm_bsize != HashGetMaxBitmapSize(metapage) ||
		metap->hashm_bmsize == 0 ||
		(metap->hashm_bmsize & (metap->hashm_bmsize - 1)) != 0 ||
		metap->hashm_bmsize > metap->hashm_bsize ||
		metap->hashm_bmshift != pg_leftmost_one_pos32(metap->hashm_bmsize) + BYTE_TO_BIT)
		ereport(ERROR,
				(errcode(ERRCODE_INDEX_CORRUPTED),
				 errmsg("index \"%s\" has inconsistent bitmap size fields in metapage",
						RelationGetRelationName(state->rel)),
				 errhint("Please REINDEX it.")));

	for (uint32 i = 1; i <= metap->hashm_ovflpoint; i++)
	{
		if (metap->hashm_spares[i] < metap->hashm_spares[i - 1])
			ereport(ERROR,
					(errcode(ERRCODE_INDEX_CORRUPTED),
					 errmsg("index \"%s\" has nonmonotonic spare page counts in metapage",
							RelationGetRelationName(state->rel)),
					 errhint("Please REINDEX it.")));
	}
}

static void
hash_check_bucket_chain(HashCheckState *state, Bucket bucket)
{
	BlockNumber blkno = BUCKET_TO_BLKNO(&state->metap, bucket);
	BlockNumber prevblkno = InvalidBlockNumber;
	bool		primary = true;
	bool		split_cleanup = false;

	if (blkno >= state->nblocks)
		ereport(ERROR,
				(errcode(ERRCODE_INDEX_CORRUPTED),
				 errmsg("index \"%s\" maps bucket %u to nonexistent block %u",
						RelationGetRelationName(state->rel), bucket, blkno),
				 errhint("Please REINDEX it.")));

	for (;;)
	{
		Buffer		buf;
		Page		page;
		HashPageOpaque opaque;

		if (blkno == InvalidBlockNumber)
			break;

		if (blkno >= state->nblocks)
			ereport(ERROR,
					(errcode(ERRCODE_INDEX_CORRUPTED),
					 errmsg("index \"%s\" bucket %u chain links to nonexistent block %u",
							RelationGetRelationName(state->rel), bucket, blkno),
					 errhint("Please REINDEX it.")));

		if (state->reachable_pages[blkno])
			ereport(ERROR,
					(errcode(ERRCODE_INDEX_CORRUPTED),
					 errmsg("index \"%s\" bucket %u chain links to block %u more than once",
							RelationGetRelationName(state->rel), bucket, blkno),
					 errhint("Please REINDEX it.")));

		if (state->bitmap_pages[blkno])
			ereport(ERROR,
					(errcode(ERRCODE_INDEX_CORRUPTED),
					 errmsg("index \"%s\" bucket %u chain links to bitmap block %u",
							RelationGetRelationName(state->rel), bucket, blkno),
					 errhint("Please REINDEX it.")));

		buf = _hash_getbuf_with_strategy(state->rel, blkno, HASH_READ,
										  primary ? LH_BUCKET_PAGE : LH_OVERFLOW_PAGE,
										  state->checkstrategy);
		page = BufferGetPage(buf);
		opaque = HashPageGetOpaque(page);

		state->reachable_pages[blkno] = true;

		hash_check_page_opaque(state, page, blkno, bucket, prevblkno,
							   primary);

		if (primary)
			split_cleanup = H_NEEDS_SPLIT_CLEANUP(opaque);

		hash_check_tuple_page(state, page, blkno, bucket, split_cleanup);

		prevblkno = blkno;
		blkno = opaque->hasho_nextblkno;
		primary = false;

		_hash_relbuf(state->rel, buf);
	}
}

static void
hash_check_page_opaque(HashCheckState *state, Page page, BlockNumber blkno,
					   Bucket bucket, BlockNumber prevblkno, bool primary)
{
	HashPageOpaque opaque = HashPageGetOpaque(page);
	uint16		pagetype = opaque->hasho_flag & LH_PAGE_TYPE;

	if (opaque->hasho_page_id != HASHO_PAGE_ID)
		ereport(ERROR,
				(errcode(ERRCODE_INDEX_CORRUPTED),
				 errmsg("index \"%s\" block %u has invalid hash page id",
						RelationGetRelationName(state->rel), blkno),
				 errhint("Please REINDEX it.")));

	if (pagetype != (primary ? LH_BUCKET_PAGE : LH_OVERFLOW_PAGE))
		ereport(ERROR,
				(errcode(ERRCODE_INDEX_CORRUPTED),
				 errmsg("index \"%s\" block %u has unexpected hash page type",
						RelationGetRelationName(state->rel), blkno),
				 errdetail_internal("Expected %s page, found %s page.",
									 primary ? "bucket" : "overflow",
									 hash_page_type_string(pagetype)),
				 errhint("Please REINDEX it.")));

	if (opaque->hasho_bucket != bucket)
		ereport(ERROR,
				(errcode(ERRCODE_INDEX_CORRUPTED),
				 errmsg("index \"%s\" block %u is in bucket %u but is marked as bucket %u",
						RelationGetRelationName(state->rel), blkno, bucket,
						opaque->hasho_bucket),
				 errhint("Please REINDEX it.")));

	if (primary)
	{
		BlockNumber expected = BUCKET_TO_BLKNO(&state->metap, bucket);

		if (blkno != expected)
			ereport(ERROR,
					(errcode(ERRCODE_INDEX_CORRUPTED),
					 errmsg("index \"%s\" bucket %u starts at block %u instead of block %u",
							RelationGetRelationName(state->rel), bucket, blkno,
							expected),
					 errhint("Please REINDEX it.")));

		if (opaque->hasho_prevblkno == InvalidBlockNumber ||
			opaque->hasho_prevblkno > state->metap.hashm_maxbucket)
			ereport(ERROR,
					(errcode(ERRCODE_INDEX_CORRUPTED),
					 errmsg("index \"%s\" bucket page %u has invalid cached max bucket %u",
							RelationGetRelationName(state->rel), blkno,
							opaque->hasho_prevblkno),
					 errhint("Please REINDEX it.")));

		if (H_BUCKET_BEING_SPLIT(opaque) || H_BUCKET_BEING_POPULATED(opaque))
			ereport(ERROR,
					(errcode(ERRCODE_INDEX_CORRUPTED),
					 errmsg("index \"%s\" bucket page %u has an unfinished split flag",
							RelationGetRelationName(state->rel), blkno),
					 errhint("Please REINDEX it.")));
	}
	else if (opaque->hasho_prevblkno != prevblkno)
		ereport(ERROR,
				(errcode(ERRCODE_INDEX_CORRUPTED),
				 errmsg("index \"%s\" overflow page %u has invalid previous block link",
						RelationGetRelationName(state->rel), blkno),
				 errdetail_internal("Expected previous block %u, found %u.",
									 prevblkno, opaque->hasho_prevblkno),
				 errhint("Please REINDEX it.")));
}

static void
hash_check_tuple_page(HashCheckState *state, Page page, BlockNumber blkno,
					  Bucket bucket, bool split_cleanup)
{
	OffsetNumber maxoff = PageGetMaxOffsetNumber(page);
	uint32		lasthashkey = 0;
	bool		first = true;
	Bucket		cleanup_bucket = InvalidBucket;

	if (split_cleanup)
		cleanup_bucket = _hash_get_newbucket_from_oldbucket(state->rel, bucket,
															state->metap.hashm_lowmask,
															state->metap.hashm_maxbucket);

	for (OffsetNumber offnum = FirstOffsetNumber;
		 offnum <= maxoff;
		 offnum = OffsetNumberNext(offnum))
		hash_check_tuple(state, page, blkno, offnum, bucket, split_cleanup,
						 cleanup_bucket, &lasthashkey, &first);
}

static void
hash_check_tuple(HashCheckState *state, Page page, BlockNumber blkno,
				 OffsetNumber offnum, Bucket bucket, bool split_cleanup,
				 Bucket cleanup_bucket, uint32 *lasthashkey, bool *first)
{
	ItemId		itemid = PageGetItemIdCareful(state, page, blkno, offnum);
	IndexTuple	itup = (IndexTuple) PageGetItem(page, itemid);
	Size		tupsize = IndexTupleSize(itup);
	Size		dataoff = IndexInfoFindDataOffset(itup->t_info);
	uint32		hashkey;
	Bucket		hashbucket;

	if (MAXALIGN(tupsize) != MAXALIGN(ItemIdGetLength(itemid)) ||
		tupsize < dataoff + sizeof(uint32))
		ereport(ERROR,
				(errcode(ERRCODE_INDEX_CORRUPTED),
				 errmsg("invalid hash index tuple size in index \"%s\"",
						RelationGetRelationName(state->rel)),
				 errdetail_internal("Index tid=(%u,%u) tuple size=%zu lp_len=%u.",
									 blkno, offnum, tupsize,
									 ItemIdGetLength(itemid))));

	if (IndexTupleHasNulls(itup) || IndexTupleHasVarwidths(itup))
		ereport(ERROR,
				(errcode(ERRCODE_INDEX_CORRUPTED),
				 errmsg("invalid hash index tuple header in index \"%s\"",
						RelationGetRelationName(state->rel)),
				 errdetail_internal("Index tid=(%u,%u) t_info=0x%04x.",
									 blkno, offnum, itup->t_info)));

	if (!ItemPointerIsValid(&itup->t_tid))
		ereport(ERROR,
				(errcode(ERRCODE_INDEX_CORRUPTED),
				 errmsg("invalid heap TID in hash index \"%s\"",
						RelationGetRelationName(state->rel)),
				 errdetail_internal("Index tid=(%u,%u).", blkno, offnum)));

	hashkey = _hash_get_indextuple_hashkey(itup);

	if (!*first && hashkey < *lasthashkey)
		ereport(ERROR,
				(errcode(ERRCODE_INDEX_CORRUPTED),
				 errmsg("hash index \"%s\" tuples are out of order on block %u",
						RelationGetRelationName(state->rel), blkno),
				 errdetail_internal("Offset %u has hash key %u after hash key %u.",
									 offnum, hashkey, *lasthashkey)));

	*first = false;
	*lasthashkey = hashkey;

	hashbucket = _hash_hashkey2bucket(hashkey,
									  state->metap.hashm_maxbucket,
									  state->metap.hashm_highmask,
									  state->metap.hashm_lowmask);

	if (hashbucket != bucket &&
		!(split_cleanup && hashbucket == cleanup_bucket))
		ereport(ERROR,
				(errcode(ERRCODE_INDEX_CORRUPTED),
				 errmsg("hash index \"%s\" tuple points to wrong bucket",
						RelationGetRelationName(state->rel)),
				 errdetail_internal("Index tid=(%u,%u) has hash key %u mapping to bucket %u, but is in bucket %u.",
									 blkno, offnum, hashkey, hashbucket,
									 bucket),
				 errhint("Please REINDEX it.")));
}

static void
hash_check_unreachable_page(HashCheckState *state, BlockNumber blkno)
{
	Buffer		buf;
	Page		page;
	HashPageOpaque opaque;
	uint16		pagetype;

	if (state->bitmap_pages[blkno])
		buf = _hash_getbuf_with_strategy(state->rel, blkno, HASH_READ,
										  LH_BITMAP_PAGE,
										  state->checkstrategy);
	else
	{
		buf = ReadBufferExtended(state->rel, MAIN_FORKNUM, blkno,
								 RBM_NORMAL, state->checkstrategy);
		LockBuffer(buf, HASH_READ);
	}

	page = BufferGetPage(buf);

	/*
	 * Hash indexes can contain all-zero pages within the relation.  New
	 * splitpoint ranges are allocated by writing an initialized page at the
	 * end of the range; intervening pages may remain filesystem holes until
	 * they become active bucket pages.
	 */
	if (PageIsNew(page))
	{
		_hash_relbuf(state->rel, buf);
		return;
	}

	_hash_checkpage(state->rel, buf, 0);

	opaque = HashPageGetOpaque(page);
	pagetype = opaque->hasho_flag & LH_PAGE_TYPE;

	if (opaque->hasho_page_id != HASHO_PAGE_ID)
		ereport(ERROR,
				(errcode(ERRCODE_INDEX_CORRUPTED),
				 errmsg("index \"%s\" block %u has invalid hash page id",
						RelationGetRelationName(state->rel), blkno),
				 errhint("Please REINDEX it.")));

	if (state->bitmap_pages[blkno])
	{
		if (pagetype != LH_BITMAP_PAGE ||
			opaque->hasho_prevblkno != InvalidBlockNumber ||
			opaque->hasho_nextblkno != InvalidBlockNumber ||
			opaque->hasho_bucket != InvalidBucket)
			ereport(ERROR,
					(errcode(ERRCODE_INDEX_CORRUPTED),
					 errmsg("index \"%s\" bitmap page %u has invalid page data",
							RelationGetRelationName(state->rel), blkno),
					 errhint("Please REINDEX it.")));
	}
	else if (pagetype == LH_UNUSED_PAGE)
	{
		if (opaque->hasho_prevblkno != InvalidBlockNumber ||
			opaque->hasho_nextblkno != InvalidBlockNumber ||
			opaque->hasho_bucket != InvalidBucket)
			ereport(ERROR,
					(errcode(ERRCODE_INDEX_CORRUPTED),
					 errmsg("index \"%s\" unused page %u has invalid page data",
							RelationGetRelationName(state->rel), blkno),
					 errhint("Please REINDEX it.")));
	}
	else
		ereport(ERROR,
				(errcode(ERRCODE_INDEX_CORRUPTED),
				 errmsg("index \"%s\" block %u is not reachable from any bucket",
						RelationGetRelationName(state->rel), blkno),
				 errdetail_internal("Found %s page.", hash_page_type_string(pagetype)),
				 errhint("Please REINDEX it.")));

	_hash_relbuf(state->rel, buf);
}

static ItemId
PageGetItemIdCareful(HashCheckState *state, Page page, BlockNumber blkno,
					 OffsetNumber offnum)
{
	ItemId		itemid = PageGetItemId(page, offnum);

	if (ItemIdGetOffset(itemid) + ItemIdGetLength(itemid) >
		PageGetPageSize(page) - MAXALIGN(sizeof(HashPageOpaqueData)))
		ereport(ERROR,
				(errcode(ERRCODE_INDEX_CORRUPTED),
				 errmsg("line pointer points past end of tuple space in hash index \"%s\"",
						RelationGetRelationName(state->rel)),
				 errdetail_internal("Index tid=(%u,%u) lp_off=%u lp_len=%u lp_flags=%u.",
									 blkno, offnum, ItemIdGetOffset(itemid),
									 ItemIdGetLength(itemid),
									 ItemIdGetFlags(itemid))));

	/*
	 * Hash indexes can mark line pointers LP_DEAD, but never use LP_REDIRECT
	 * or LP_UNUSED for index tuples.  Verify that every used line pointer has
	 * storage, including LP_DEAD items.
	 */
	if (ItemIdIsRedirected(itemid) || !ItemIdIsUsed(itemid) ||
		ItemIdGetLength(itemid) == 0)
		ereport(ERROR,
				(errcode(ERRCODE_INDEX_CORRUPTED),
				 errmsg("invalid line pointer storage in hash index \"%s\"",
						RelationGetRelationName(state->rel)),
				 errdetail_internal("Index tid=(%u,%u) lp_off=%u lp_len=%u lp_flags=%u.",
									 blkno, offnum, ItemIdGetOffset(itemid),
									 ItemIdGetLength(itemid),
									 ItemIdGetFlags(itemid))));

	return itemid;
}

static const char *
hash_page_type_string(uint16 pagetype)
{
	switch (pagetype)
	{
		case LH_UNUSED_PAGE:
			return "unused";
		case LH_OVERFLOW_PAGE:
			return "overflow";
		case LH_BUCKET_PAGE:
			return "bucket";
		case LH_BITMAP_PAGE:
			return "bitmap";
		case LH_META_PAGE:
			return "meta";
		default:
			return "unknown";
	}
}

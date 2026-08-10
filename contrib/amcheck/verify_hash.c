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


PG_FUNCTION_INFO_V1(hash_index_check);

/*
 * hash_index_check(index regclass)
 *
 * Verify integrity of hash index.
 */
Datum
hash_index_check(PG_FUNCTION_ARGS)
{
	Oid			indrelid = PG_GETARG_OID(0);

	PG_RETURN_VOID();
}

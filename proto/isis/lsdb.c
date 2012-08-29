/*
 *	BIRD -- IS-IS LSP database
 *
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */


static inline int
isis_lsp_comp(struct isis_lsp_hdr *l1, struct isis_lsp_hdr *l2)
{
  if (l1->seqnum != l2->seqnum)
    return (l1->seqnum > l2->seqnum) ? LSP_NEWER : LSP_OLDER;

  // XXX review
  if (l1->checksum != l2->checksum)
    return (l1->checksum > l2->checksum) ? LSP_NEWER : LSP_OLDER;

  return LSP_SAME;
}

struct isis_lsp *
isis_get_lsp(struct isis_lsdb *db, xxx)
{
}


void
isis_lsp_received(struct isis_lsdb *db, struct isis_iface *ifa,
		  struct isis_lsp_hdr *hdr, byte *body, int blen)
{
  struct isis_lsp *lsp = isis_get_lsp(db, hdr);

  int cmp = isis_lsp_comp(hdr, &lsp->hdr);
  switch (cmp)
  {
  LSP_NEWER:
    xxx();
  LSP_SAME:
    isis_lsp_clear_srm(lsp, ifa);
    isis_lsp_set_ack(lsp, ifa);
    break;

  LSP_OLDER:
    isis_lsp_set_srm(lsp, ifa);
    isis_lsp_clear_ssn(lsp, ifa);
    break;
  }
}

void
isis_snp_received(struct isis_lsdb *db, struct isis_iface *ifa, struct isis_lsp_hdr *hdr)
{
  struct isis_lsp *lsp = isis_get_lsp(db, hdr);

  int cmp = isis_lsp_comp(hdr, &lsp->hdr);
  switch (cmp)
  {
  LSP_NEWER:
    isis_lsp_set_ssn(lsp, ifa);
  LSP_SAME:
    isis_lsp_clear_ack(lsp, ifa);
    break;

  LSP_OLDER:
    isis_lsp_set_srm(lsp, ifa);
    isis_lsp_clear_ssn(lsp, ifa);
    break;
  }

  isis_lsp_clear_csnp(lsp);
}

struct isis_lsdb *
isis_lsdb_new(struct isis_proto *p)
{
  pool *pool = rp_new(p->p.pool, "ISIS LSP database");
  struct isis_lsdb *db = mb_allocz(pool, sizeof(struct isis_lsdb));

  db->pool = pool;
  db->slab = sl_new(pool, sizeof(struct lsp_entry));
  init_list(&db->list);
}

void
isis_lsdb_free(struct isis_lsdb *db)
{
  rfree(db->pool);
}

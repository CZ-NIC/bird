/*
 *	BIRD Internet Routing Daemon -- MPLS Structures
 *
 *	(c) 2022 Ondrej Zajicek <santiago@crfreenet.org>
 *	(c) 2022 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

CF_HDR

#include "nest/mpls.h"

CF_DEFINES

static struct mpls_domain_config *this_mpls_domain;
static struct mpls_range_config *this_mpls_range;

#define MPLS_CC ((struct mpls_channel_config *) this_channel)

CF_DECLS

CF_KEYWORDS(MPLS, DOMAIN, LABEL, RANGE, STATIC, DYNAMIC, START, LENGTH, POLICY, PREFIX, AGGREGATE, VRF)

%type <i> mpls_label_policy
%type <cc> mpls_channel_start mpls_channel
%type <msrc> show_mpls_ranges_args

CF_GRAMMAR

conf: mpls_domain;

mpls_domain: mpls_domain_start mpls_domain_opt_list mpls_domain_end;

mpls_domain_start: MPLS DOMAIN symbol { this_mpls_domain = mpls_domain_config_new($3); };

mpls_domain_opt:
   mpls_range
 ;

mpls_domain_opts:
   /* empty */
 | mpls_domain_opts mpls_domain_opt ';'
 ;

mpls_domain_opt_list:
   /* empty */
 | '{' mpls_domain_opts '}'
 ;

mpls_domain_end: { mpls_domain_postconfig(this_mpls_domain); this_mpls_domain = NULL; };


mpls_range: mpls_range_start mpls_range_opt_list mpls_range_end;

mpls_range_start: LABEL RANGE symbol
{
  if (($3->class == SYM_KEYWORD) && ($3->keyword->value == STATIC))
    this_mpls_range = this_mpls_domain->static_range;
  else if (($3->class == SYM_KEYWORD) && ($3->keyword->value == DYNAMIC))
    this_mpls_range = this_mpls_domain->dynamic_range;
  else
    this_mpls_range = mpls_range_config_new(this_mpls_domain, $3);
};

mpls_range_opt:
   START expr { this_mpls_range->start = $2; if ($2 >= MPLS_MAX_LABEL) cf_error("MPLS label range start must be less than 2^20"); }
 | LENGTH expr { this_mpls_range->length = $2; if ($2 >= MPLS_MAX_LABEL) cf_error("MPLS label range length must be less than 2^20"); if (!$2) cf_error("MPLS label range length must be nonzero"); }
 ;

mpls_range_opts:
   /* empty */
 | mpls_range_opts mpls_range_opt ';'
 ;

mpls_range_opt_list:
   /* empty */
 | '{' mpls_range_opts '}'
 ;

mpls_range_end:
{
  struct mpls_range_config *r = this_mpls_range;

  if ((r->start == (uint) -1) || (r->length == (uint) -1))
    cf_error("MPLS label range start and length must be specified");

  if (r->start + r->length > MPLS_MAX_LABEL)
    cf_error("MPLS label range end must be less than 2^20");

  this_mpls_range = NULL;
};


mpls_channel: mpls_channel_start mpls_channel_opt_list mpls_channel_end;

mpls_channel_start: MPLS
{
  $$ = this_channel = channel_config_get(&channel_mpls, net_label[NET_MPLS], NET_MPLS, this_proto);

  if (EMPTY_LIST(new_config->mpls_domains))
  {
    int counter = 0;
    mpls_domain_config_new(cf_default_name(new_config, "mpls%d", &counter));
    cf_warn("No MPLS domain defined");
  }

  /* Default values for new channel */
  if (!MPLS_CC->domain)
  {
    MPLS_CC->domain = cf_default_mpls_domain(new_config);
    MPLS_CC->label_policy = MPLS_POLICY_PREFIX;
  }
};

mpls_label_policy:
   STATIC { $$ = MPLS_POLICY_STATIC; }
 | PREFIX { $$ = MPLS_POLICY_PREFIX; }
 | AGGREGATE { $$ = MPLS_POLICY_AGGREGATE; }
 | VRF { $$ = MPLS_POLICY_VRF; }
 ;

mpls_channel_opt:
   channel_item
 | DOMAIN symbol_known { cf_assert_symbol($2, SYM_MPLS_DOMAIN); MPLS_CC->domain = $2->mpls_domain; }
 | LABEL RANGE symbol_known { cf_assert_symbol($3, SYM_MPLS_RANGE); MPLS_CC->range = $3->mpls_range; }
 | LABEL RANGE STATIC  { MPLS_CC->range = MPLS_CC->domain->static_range; }
 | LABEL RANGE DYNAMIC { MPLS_CC->range = MPLS_CC->domain->dynamic_range; }
 | LABEL POLICY mpls_label_policy { MPLS_CC->label_policy = $3; }
 ;

mpls_channel_opts:
   /* empty */
 | mpls_channel_opts mpls_channel_opt ';'
 ;

mpls_channel_opt_list:
   /* empty */
 | '{' mpls_channel_opts '}'
 ;

mpls_channel_end: { mpls_channel_postconfig(this_channel); } channel_end;


show_mpls_ranges_args:
   /* empty */
   {
     if (EMPTY_LIST(config->mpls_domains))
       cf_error("No MPLS domain defined");

     $$ = cfg_allocz(sizeof(struct mpls_show_ranges_cmd));
   }
 | show_mpls_ranges_args symbol_known
   {
     if ($2->class == SYM_MPLS_DOMAIN)
     {
       if ($$->domain)
	cf_error("Only one MPLS domain expected");

       $$->domain = $2->mpls_domain;
     }
     else if ($2->class == SYM_MPLS_RANGE)
     {
       if ($$->range)
	cf_error("Only one MPLS label range expected");

       if ($$->domain != $2->mpls_range->domain)
	cf_error("MPLS label range from different MPLS domain");

       $$->domain = $2->mpls_range->domain;
       $$->range = $2->mpls_range;
     }
     else
       cf_error("MPLS domain or label range expected");
   }
 | show_mpls_ranges_args STATIC
   {
     if ($$->range)
       cf_error("Only one MPLS label range expected");

     $$->domain = $$->domain ?: cf_default_mpls_domain(config);
     $$->range = $$->domain->static_range;
   }
 | show_mpls_ranges_args DYNAMIC
   {
     if ($$->range)
       cf_error("Only one MPLS label range expected");

     $$->domain = $$->domain ?: cf_default_mpls_domain(config);
     $$->range = $$->domain->dynamic_range;
   }
 ;

CF_CLI(SHOW MPLS RANGES, show_mpls_ranges_args, [<MPLS domain> | <MPLS range>], [[Show MPLS ranges]])
{ mpls_show_ranges($4); } ;


CF_CODE

CF_END

#ifndef _BIRD_STATS_PUB_H_
#define _BIRD_STATS_PUB_H_

extern int stats_get_counter(struct symbol *sym);
extern struct f_val stats_eval_term(struct stats_term_config *tc);
extern int  stats_get_type(struct stats_term_config *tc);
#endif

/*
 *	BIRD Internet Routing Daemon -- Filters
 *
 *	(c) 1999 Pavel Machek <pavel@ucw.cz>
 *	(c) 2018 Maria Matejka <mq@jmq.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_FILTER_UTIL_H_
#define _BIRD_FILTER_UTIL_H_

struct f_inst *f_new_inst(struct cf_context *ctx, enum f_instruction_code fi_code);
struct f_inst *f_new_inst_da(struct cf_context *ctx, enum f_instruction_code fi_code, struct f_dynamic_attr da);
struct f_inst *f_new_inst_sa(struct cf_context *ctx, enum f_instruction_code fi_code, struct f_static_attr sa);
static inline struct f_dynamic_attr f_new_dynamic_attr(int type, int f_type, int code) /* Type as core knows it, type as filters know it, and code of dynamic attribute */
{ return (struct f_dynamic_attr) { .type = type, .f_type = f_type, .ea_code = code }; }   /* f_type currently unused; will be handy for static type checking */
static inline struct f_static_attr f_new_static_attr(int f_type, int code, int readonly)
{ return (struct f_static_attr) { .f_type = f_type, .sa_code = code, .readonly = readonly }; }
struct f_tree *f_new_tree(struct cf_context *ctx);
struct f_inst *f_generate_complex(struct cf_context *ctx, int operation, int operation_aux, struct f_dynamic_attr da, struct f_inst *argument);
struct f_inst *f_generate_roa_check(struct cf_context *ctx, struct rtable_config *table, struct f_inst *prefix, struct f_inst *asn);

uint f_eval_int(struct f_inst *expr, struct cf_context *ctx);

#endif

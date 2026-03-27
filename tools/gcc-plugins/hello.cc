#include "gcc-plugin.h"

#include "context.h"
#include "config.h"
#include "tree.h"
#include "tree-pass.h"
#include "gimple.h"
#include "gimple-iterator.h"

#include <iostream>
#include <string>

int plugin_is_GPL_compatible;

namespace bird {
  static const pass_data bird_atomic_info_data = {
    .type = GIMPLE_PASS,
    .name = "bird_atomic_info",
    .tv_id = TV_NONE,
    .properties_required = PROP_gimple_any,
  };

  static const std::string type_name(const_tree t)
  {
    if (!t)
      return "<nothing>";

//    std::cerr << "Q";

    if (TREE_CODE(t) == POINTER_TYPE)
//      return "<ptr>";
      return bird::type_name(TREE_TYPE(t)) + "*";

//    std::cerr << "W";

    if (TREE_CODE_CLASS(TREE_CODE(t)) != tcc_type)
      return "not-a-type";

//    std::cerr << "E";
    auto tname = TYPE_NAME(t);
    if (!tname)
      return "unnamed-type";

    if (TREE_CODE(tname) == IDENTIFIER_NODE)
      return IDENTIFIER_POINTER(tname);

//    std::cerr << "R";
    if (TREE_CODE(tname) != TYPE_DECL)
      return "weird-type";

//    std::cerr << "T";
    auto dname = DECL_NAME(tname);
    if (dname)
      return IDENTIFIER_POINTER(dname);

//    std::cerr << "Y";
    return "unnamed-decl";
  }

  class bird_atomic_info: public gimple_opt_pass {
    public:
      bird_atomic_info(gcc::context *ctx):gimple_opt_pass(bird_atomic_info_data, ctx) {}
      static void gimple_atomic_info(gimple_seq gs) {
	for (gimple_stmt_iterator gsi = gsi_start(gs); !gsi_end_p(gsi); gsi_next(&gsi))
	{
	  auto stmt = gsi_stmt(gsi);
	  switch (gimple_code(stmt)) {
	    case GIMPLE_BIND:
	      gimple_atomic_info(gimple_bind_body(dyn_cast<gbind*>(stmt)));
	      break;
	    case GIMPLE_TRY:
	      gimple_atomic_info(gimple_try_eval(stmt));
	      gimple_atomic_info(gimple_try_cleanup(stmt));
	      break;

	    case GIMPLE_CALL:
	      {
		auto fn = gimple_call_fndecl(stmt);
		if (!fn) {
//		  fprintf(stderr, "fn is null\n");
		  return;
		}

		const char *name = get_name(fn);
		if (strncmp("__atomic_", name, 9))
		  break;

		int nargs = gimple_call_num_args(stmt);
		fprintf(stderr, "Builtin(%d) %s", nargs, name);
		for (int i=0; i<nargs; i++)
		{
		  auto arg = gimple_call_arg(stmt, i);
//		  fprintf(stderr, " %p", arg);
		  std::cerr << (i ? ", " : "(") << bird::type_name(TREE_TYPE(arg));
		}

		std::cerr << ")\n";

#if 0
		const char *name = get_name(fn);
		auto fnd = &fn->function_decl;
		if (!strncmp("__atomic_", name, 9))
		{
//		fprintf(stderr, "fn: %p / %s\n", fn, std::to_string(DECL_UID(fn)));
		  fprintf(stderr, "atomic %s%c%c%c%c%c%c%c%c%c%c%c%c%c%c\n", name,
		      " C"[fnd->static_ctor_flag],
		      " D"[fnd->static_dtor_flag],
		      " U"[fnd->uninlinable],
		      " I"[fnd->possibly_inlined],
		      " N"[fnd->novops_flag],
		      " 2"[fnd->returns_twice_flag],
		      " M"[fnd->malloc_flag],
		      " i"[fnd->declared_inline_flag],
		      " w"[fnd->no_inline_warning_flag],
		      " e"[fnd->no_instrument_function_entry_exit],
		      " s"[fnd->no_limit_stack],
		      " L"[fnd->disregard_inline_limits],
		      " P"[fnd->pure_flag],
		      " o"[fnd->looping_const_or_pure_flag]
		      );

		  int cnt = 0;
		  for (auto arg = DECL_ARGUMENTS(fn); arg; arg = DECL_CHAIN(arg))
		  {
//		    fprintf(stderr, "  arg %s\n", type_name(TREE_TYPE(arg)));
		    cnt++;
		  }

		  fprintf(stderr, "args: %d\n", cnt);
		}
		else
		{
		  fprintf(stderr, "other %s%c%c%c%c%c%c%c%c%c%c%c%c%c%c\n", name,
		      " C"[fnd->static_ctor_flag],
		      " D"[fnd->static_dtor_flag],
		      " U"[fnd->uninlinable],
		      " I"[fnd->possibly_inlined],
		      " N"[fnd->novops_flag],
		      " 2"[fnd->returns_twice_flag],
		      " M"[fnd->malloc_flag],
		      " i"[fnd->declared_inline_flag],
		      " w"[fnd->no_inline_warning_flag],
		      " e"[fnd->no_instrument_function_entry_exit],
		      " s"[fnd->no_limit_stack],
		      " L"[fnd->disregard_inline_limits],
		      " P"[fnd->pure_flag],
		      " o"[fnd->looping_const_or_pure_flag]
		      );

		  int cnt = 0;
		  for (auto arg = DECL_ARGUMENTS(fn); arg; arg = DECL_CHAIN(arg))
		  {
//		    fprintf(stderr, "  arg %s\n", type_name(TREE_TYPE(arg)));
		    cnt++;
		  }

		  fprintf(stderr, "args: %d\n", cnt);
		}
#endif
		break;
	      }

	    default:
	//      fprintf(stderr, "nya\n");
	      break;
	  }
	}
      }

      virtual unsigned int execute(function *fn) override {
//	fprintf(stderr, "Function %s\n", function_name(fn));
	gimple_atomic_info(fn->gimple_body);
	return 0;
      }
      virtual bird_atomic_info *clone() override {
	return this;
      }
  };
};

int plugin_init(struct plugin_name_args *plugin_info, struct plugin_gcc_version *version)
{
  const char * const plugin_name = plugin_info->base_name;
//  fprintf(stderr, "Plugin init start: %s\n", plugin_name);
  struct register_pass_info atomic_info = {
    .pass = new bird::bird_atomic_info(g),
    .reference_pass_name = "lower",
    .ref_pass_instance_number = 1,
    .pos_op = PASS_POS_INSERT_AFTER,
  };
  register_callback(plugin_name, PLUGIN_PASS_MANAGER_SETUP, NULL, &atomic_info);
//  fprintf(stderr, "Plugin init done: %s\n", plugin_name);
  return 0;
}

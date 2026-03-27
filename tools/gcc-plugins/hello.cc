#include "gcc-plugin.h"

#include "context.h"
#include "tree-pass.h"

int plugin_is_GPL_compatible;

namespace bird {
  static const pass_data bird_atomic_info_data = {
    .type = GIMPLE_PASS,
    .name = "bird_atomic_info",
    .tv_id = TV_NONE,
    .properties_required = PROP_gimple_any,
  };

  class bird_atomic_info: public gimple_opt_pass {
    public:
      bird_atomic_info(gcc::context *ctx):gimple_opt_pass(bird_atomic_info_data, ctx) {}
      virtual unsigned int execute(function *fn) override {
	fprintf(stderr, "Function %s\n", function_name(fn));
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
  fprintf(stderr, "Plugin init start: %s\n", plugin_name);
  struct register_pass_info atomic_info = {
    .pass = new bird::bird_atomic_info(g),
    .reference_pass_name = "lower",
    .ref_pass_instance_number = 1,
    .pos_op = PASS_POS_INSERT_AFTER,
  };
  register_callback(plugin_name, PLUGIN_PASS_MANAGER_SETUP, NULL, &atomic_info);
  fprintf(stderr, "Plugin init done: %s\n", plugin_name);
  return 0;
}

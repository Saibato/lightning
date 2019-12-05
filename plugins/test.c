#include <bitcoin/chainparams.c>
#include <ccan/array_size/array_size.h>
#include <ccan/json_out/json_out.h>
#include <plugins/libplugin.h>

/* test hook and notification plugins */ 

static void init(struct plugin_conn *rpc,
		 const char *buf UNUSED, const jsmntok_t *config UNUSED)
{
}

static struct command_result *json_hook(struct command *cmd,
					       const char *buf,
					       const jsmntok_t *params)
{
	struct json_out *ret;

	plugin_log(LOG_DBG, "hook: '%s'", buf);

	ret = json_out_new(NULL);
	json_out_start(ret, NULL, '{');
	json_out_addstr(ret, "result", "continue");
	json_out_end(ret, '}');

	return command_success(cmd, ret);
}

static void json_notificate(struct command *cmd,
					       const char *buf,
					       const jsmntok_t *params)
{
	plugin_log(LOG_DBG, "notification: '%s'", buf);
	return;
}

const struct plugin_notification command_notification[] = { {
		"connect",
		json_notificate
	},
};


const struct plugin_hook command_hook[] = { {
		"peer_connected",
		json_hook
	},
};


int main(int argc, char *argv[])
{
	setup_locale();
	plugin_main(argv, init, PLUGIN_RESTARTABLE, NULL, 0,
	            command_notification, ARRAY_SIZE(command_notification),
	            command_hook, ARRAY_SIZE(command_hook)
	             , NULL);
}

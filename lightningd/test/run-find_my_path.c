#define main unused_main
int unused_main(int argc, char *argv[]);
#include "../../common/base32.c"
#include "../../common/wireaddr.c"
#include "../../common/tor.c"
#include "../lightningd.c"

/* AUTOGENERATED MOCKS START */
/* Generated stub for activate_peers */
void activate_peers(struct lightningd *ld UNNEEDED)
{ fprintf(stderr, "activate_peers called!\n"); abort(); }
/* Generated stub for begin_topology */
void begin_topology(struct chain_topology *topo UNNEEDED)
{ fprintf(stderr, "begin_topology called!\n"); abort(); }
/* Generated stub for crashlog_activate */
void crashlog_activate(const char *argv0 UNNEEDED, struct log *log UNNEEDED)
{ fprintf(stderr, "crashlog_activate called!\n"); abort(); }
/* Generated stub for db_begin_transaction_ */
void db_begin_transaction_(struct db *db UNNEEDED, const char *location UNNEEDED)
{ fprintf(stderr, "db_begin_transaction_ called!\n"); abort(); }
/* Generated stub for db_close_for_fork */
void db_close_for_fork(struct db *db UNNEEDED)
{ fprintf(stderr, "db_close_for_fork called!\n"); abort(); }
/* Generated stub for db_commit_transaction */
void db_commit_transaction(struct db *db UNNEEDED)
{ fprintf(stderr, "db_commit_transaction called!\n"); abort(); }
/* Generated stub for db_get_intvar */
s64 db_get_intvar(struct db *db UNNEEDED, char *varname UNNEEDED, s64 defval UNNEEDED)
{ fprintf(stderr, "db_get_intvar called!\n"); abort(); }
/* Generated stub for db_reopen_after_fork */
void db_reopen_after_fork(struct db *db UNNEEDED)
{ fprintf(stderr, "db_reopen_after_fork called!\n"); abort(); }
/* Generated stub for debug_poll */
int debug_poll(struct pollfd *fds UNNEEDED, nfds_t nfds UNNEEDED, int timeout UNNEEDED)
{ fprintf(stderr, "debug_poll called!\n"); abort(); }
/* Generated stub for fatal */
void   fatal(const char *fmt UNNEEDED, ...)
{ fprintf(stderr, "fatal called!\n"); abort(); }
/* Generated stub for free_htlcs */
void free_htlcs(struct lightningd *ld UNNEEDED, const struct channel *channel UNNEEDED)
{ fprintf(stderr, "free_htlcs called!\n"); abort(); }
/* Generated stub for gossip_init */
void gossip_init(struct lightningd *ld UNNEEDED)
{ fprintf(stderr, "gossip_init called!\n"); abort(); }
/* Generated stub for handle_opts */
bool handle_opts(struct lightningd *ld UNNEEDED, int argc UNNEEDED, char *argv[])
{ fprintf(stderr, "handle_opts called!\n"); abort(); }
/* Generated stub for hash_htlc_key */
size_t hash_htlc_key(const struct htlc_key *htlc_key UNNEEDED)
{ fprintf(stderr, "hash_htlc_key called!\n"); abort(); }
/* Generated stub for hsm_init */
void hsm_init(struct lightningd *ld UNNEEDED, bool newdir UNNEEDED)
{ fprintf(stderr, "hsm_init called!\n"); abort(); }
/* Generated stub for json_escape */
struct json_escaped *json_escape(const tal_t *ctx UNNEEDED, const char *str TAKES UNNEEDED)
{ fprintf(stderr, "json_escape called!\n"); abort(); }
/* Generated stub for log_ */
void log_(struct log *log UNNEEDED, enum log_level level UNNEEDED, const char *fmt UNNEEDED, ...)

{ fprintf(stderr, "log_ called!\n"); abort(); }
/* Generated stub for new_log */
struct log *new_log(const tal_t *ctx UNNEEDED, struct log_book *record UNNEEDED, const char *fmt UNNEEDED, ...)
{ fprintf(stderr, "new_log called!\n"); abort(); }
/* Generated stub for new_log_book */
struct log_book *new_log_book(size_t max_mem UNNEEDED,
			      enum log_level printlevel UNNEEDED)
{ fprintf(stderr, "new_log_book called!\n"); abort(); }
/* Generated stub for new_topology */
struct chain_topology *new_topology(struct lightningd *ld UNNEEDED, struct log *log UNNEEDED)
{ fprintf(stderr, "new_topology called!\n"); abort(); }
/* Generated stub for register_opts */
void register_opts(struct lightningd *ld UNNEEDED)
{ fprintf(stderr, "register_opts called!\n"); abort(); }
/* Generated stub for setup_color_and_alias */
void setup_color_and_alias(struct lightningd *ld UNNEEDED)
{ fprintf(stderr, "setup_color_and_alias called!\n"); abort(); }
/* Generated stub for setup_jsonrpc */
void setup_jsonrpc(struct lightningd *ld UNNEEDED, const char *rpc_filename UNNEEDED)
{ fprintf(stderr, "setup_jsonrpc called!\n"); abort(); }
/* Generated stub for setup_topology */
void setup_topology(struct chain_topology *topology UNNEEDED,
		    struct timers *timers UNNEEDED,
		    struct timerel poll_time UNNEEDED, u32 first_channel_block UNNEEDED)
{ fprintf(stderr, "setup_topology called!\n"); abort(); }
/* Generated stub for subd_shutdown */
void subd_shutdown(struct subd *subd UNNEEDED, unsigned int seconds UNNEEDED)
{ fprintf(stderr, "subd_shutdown called!\n"); abort(); }
/* Generated stub for timer_expired */
void timer_expired(tal_t *ctx UNNEEDED, struct timer *timer UNNEEDED)
{ fprintf(stderr, "timer_expired called!\n"); abort(); }
/* Generated stub for txfilter_add_derkey */
void txfilter_add_derkey(struct txfilter *filter UNNEEDED,
			 const u8 derkey[PUBKEY_DER_LEN])
{ fprintf(stderr, "txfilter_add_derkey called!\n"); abort(); }
/* Generated stub for txfilter_new */
struct txfilter *txfilter_new(const tal_t *ctx UNNEEDED)
{ fprintf(stderr, "txfilter_new called!\n"); abort(); }
/* Generated stub for version */
const char *version(void)
{ fprintf(stderr, "version called!\n"); abort(); }
/* Generated stub for wallet_channels_load_active */
bool wallet_channels_load_active(const tal_t *ctx UNNEEDED, struct wallet *w UNNEEDED)
{ fprintf(stderr, "wallet_channels_load_active called!\n"); abort(); }
/* Generated stub for wallet_first_blocknum */
u32 wallet_first_blocknum(struct wallet *w UNNEEDED, u32 first_possible UNNEEDED)
{ fprintf(stderr, "wallet_first_blocknum called!\n"); abort(); }
/* Generated stub for wallet_htlcs_load_for_channel */
bool wallet_htlcs_load_for_channel(struct wallet *wallet UNNEEDED,
				   struct channel *chan UNNEEDED,
				   struct htlc_in_map *htlcs_in UNNEEDED,
				   struct htlc_out_map *htlcs_out UNNEEDED)
{ fprintf(stderr, "wallet_htlcs_load_for_channel called!\n"); abort(); }
/* Generated stub for wallet_htlcs_reconnect */
bool wallet_htlcs_reconnect(struct wallet *wallet UNNEEDED,
			    struct htlc_in_map *htlcs_in UNNEEDED,
			    struct htlc_out_map *htlcs_out UNNEEDED)
{ fprintf(stderr, "wallet_htlcs_reconnect called!\n"); abort(); }
/* Generated stub for wallet_invoice_autoclean */
void wallet_invoice_autoclean(struct wallet * wallet UNNEEDED,
			      u64 cycle_seconds UNNEEDED,
			      u64 expired_by UNNEEDED)
{ fprintf(stderr, "wallet_invoice_autoclean called!\n"); abort(); }
/* Generated stub for wallet_invoice_load */
bool wallet_invoice_load(struct wallet *wallet UNNEEDED)
{ fprintf(stderr, "wallet_invoice_load called!\n"); abort(); }
/* Generated stub for wallet_network_check */
bool wallet_network_check(struct wallet *w UNNEEDED,
			  const struct chainparams *chainparams UNNEEDED)
{ fprintf(stderr, "wallet_network_check called!\n"); abort(); }
/* Generated stub for wallet_new */
struct wallet *wallet_new(struct lightningd *ld UNNEEDED,
			  struct log *log UNNEEDED, struct timers *timers UNNEEDED)
{ fprintf(stderr, "wallet_new called!\n"); abort(); }
/* AUTOGENERATED MOCKS END */

/* We only need these in developer mode */
#if DEVELOPER
/* Generated stub for opt_subd_debug */
char *opt_subd_debug(const char *optarg UNNEEDED, struct lightningd *ld UNNEEDED)
{ fprintf(stderr, "opt_subd_debug called!\n"); abort(); }
/* Generated stub for opt_subd_dev_disconnect */
char *opt_subd_dev_disconnect(const char *optarg UNNEEDED, struct lightningd *ld UNNEEDED)
{ fprintf(stderr, "opt_subd_dev_disconnect called!\n"); abort(); }
#endif

#undef main
int main(int argc UNUSED, char *argv[] UNUSED)
{
	char *argv0;
	/* We're assuming we're run from top build dir. */
	const char *answer;

	setup_tmpctx();
	answer = path_canon(tmpctx, "lightningd/test");

	/* Various different ways we could find ourselves. */
	argv0 = path_join(tmpctx,
			  path_cwd(tmpctx), "lightningd/test/run-find_my_path");
	unsetenv("PATH");

	/* Absolute path. */
	assert(streq(find_my_path(tmpctx, argv0), answer));

	/* Relative to cwd. */
	argv0 = "lightningd/test/run-find_my_path";
	assert(streq(find_my_path(tmpctx, argv0), answer));

	/* Using $PATH */
	setenv("PATH", path_join(tmpctx,
				 path_cwd(tmpctx), "lightningd/test"), 1);
	argv0 = "run-find_my_path";

	assert(streq(find_my_path(tmpctx, argv0), answer));

	/* Even with dummy things in path. */
	char **pathelems = tal_arr(tmpctx, char *, 4);
	pathelems[0] = "/tmp/foo";
	pathelems[1] = "/sbin";
	pathelems[2] = path_join(tmpctx, path_cwd(tmpctx), "lightningd/test");
	pathelems[3] = NULL;

	setenv("PATH", tal_strjoin(tmpctx, pathelems, ":", STR_NO_TRAIL), 1);
	assert(streq(find_my_path(tmpctx, argv0), answer));

	assert(!taken_any());
	take_cleanup();
	tal_free(tmpctx);
	return 0;
}

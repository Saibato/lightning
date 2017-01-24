#ifndef LIGHTNING_TYPE_TO_STRING_H
#define LIGHTNING_TYPE_TO_STRING_H
#include "config.h"
#include "utils.h"
#include <ccan/autodata/autodata.h>
#include <secp256k1.h>

/* This must match the type_to_string_ cases. */
union printable_types {
	const struct pubkey *pubkey;
	const struct sha256_double *sha256_double;
	const struct sha256 *sha256;
	const struct rel_locktime *rel_locktime;
	const struct abs_locktime *abs_locktime;
	const struct bitcoin_tx *bitcoin_tx;
	const struct htlc *htlc;
	const struct rval *rval;
	const struct channel_state *channel_state;
	const struct channel_oneside *channel_oneside;
	const struct netaddr *netaddr;
	const secp256k1_pubkey *secp256k1_pubkey;
	const struct channel_id *channel_id;
	const char *charp_;
};

#define type_to_string(ctx, type, ptr)					\
	type_to_string_((ctx), stringify(type),				\
			((void)sizeof((ptr) == (type *)NULL),		\
			 ((union printable_types)((const type *)ptr))))

char *type_to_string_(const tal_t *ctx, const char *typename,
		      union printable_types u);

#define REGISTER_TYPE_TO_STRING(typename, fmtfn)			\
	static char *fmt_##typename##_(const tal_t *ctx,		\
				       union printable_types u)		\
	{								\
		return fmtfn(ctx, u.typename);				\
	}								\
	static struct type_to_string ttos_##typename = {		\
		#typename, fmt_##typename##_				\
	};								\
	AUTODATA(type_to_string, &ttos_##typename)

#define REGISTER_TYPE_TO_HEXSTR(typename)				\
	static char *fmt_##typename##_(const tal_t *ctx,		\
				       union printable_types u)		\
	{								\
		return tal_hexstr(ctx, u.typename, sizeof(*u.typename)); \
	}								\
	static struct type_to_string ttos_##typename = {		\
		#typename, fmt_##typename##_				\
	};								\
	AUTODATA(type_to_string, &ttos_##typename)

struct type_to_string {
	const char *typename;
	char *(*fmt)(const tal_t *ctx, union printable_types u);
};
AUTODATA_TYPE(type_to_string, struct type_to_string);
#endif /* LIGHTNING_UTILS_H */

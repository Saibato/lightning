#include "../common/base32.c"
#include "../common/wireaddr.c"

#include <stdio.h>
#include <assert.h>
#include <ccan/mem/mem.h>

/* AUTOGENERATED MOCKS START */
/* Generated stub for fromwire */
const u8 *fromwire(const u8 **cursor UNNEEDED, size_t *max UNNEEDED, void *copy UNNEEDED, size_t n UNNEEDED)
{ fprintf(stderr, "fromwire called!\n"); abort(); }
/* Generated stub for fromwire_u16 */
u16 fromwire_u16(const u8 **cursor UNNEEDED, size_t *max UNNEEDED)
{ fprintf(stderr, "fromwire_u16 called!\n"); abort(); }
/* Generated stub for fromwire_u8 */
u8 fromwire_u8(const u8 **cursor UNNEEDED, size_t *max UNNEEDED)
{ fprintf(stderr, "fromwire_u8 called!\n"); abort(); }
/* Generated stub for towire */
void towire(u8 **pptr UNNEEDED, const void *data UNNEEDED, size_t len UNNEEDED)
{ fprintf(stderr, "towire called!\n"); abort(); }
/* Generated stub for towire_u16 */
void towire_u16(u8 **pptr UNNEEDED, u16 v UNNEEDED)
{ fprintf(stderr, "towire_u16 called!\n"); abort(); }
/* Generated stub for towire_u8 */
void towire_u8(u8 **pptr UNNEEDED, u8 v UNNEEDED)
{ fprintf(stderr, "towire_u8 called!\n"); abort(); }
/* AUTOGENERATED MOCKS END */

int main(void)
{
	struct wireaddr addr;
	char *ip;
	u16 port;

	setup_tmpctx();

	/* Grossly invalid. */
	assert(!separate_address_and_port(tmpctx, "[", &ip, &port));
	assert(!separate_address_and_port(tmpctx, "[123", &ip, &port));
	assert(!separate_address_and_port(tmpctx, "[::1]:8f", &ip, &port));
	assert(!separate_address_and_port(tmpctx, "127.0.0.1:8f", &ip, &port));
	assert(!separate_address_and_port(tmpctx, "127.0.0.1:0", &ip, &port));
	assert(!separate_address_and_port(tmpctx, "127.0.0.1:ff", &ip, &port));

	/* ret = getaddrinfo("[::1]:80", NULL, NULL, &res); */
	assert(separate_address_and_port(tmpctx, "[::1]:80", &ip, &port));
	assert(streq(ip, "::1"));
	assert(port == 80);

	port = 0;
	assert(separate_address_and_port(tmpctx, "ip6-localhost", &ip, &port));
	assert(streq(ip, "ip6-localhost"));
	assert(port == 0);

	assert(separate_address_and_port(tmpctx, "::1", &ip, &port));
	assert(streq(ip, "::1"));
	assert(port == 0);

	assert(separate_address_and_port(tmpctx, "192.168.1.1:8000", &ip, &port));
	assert(streq(ip, "192.168.1.1"));
	assert(port == 8000);

	port = 0;
	assert(separate_address_and_port(tmpctx, "192.168.2.255", &ip, &port));
	assert(streq(ip, "192.168.2.255"));
	assert(port == 0);

	// unusual but possibly valid case
	assert(separate_address_and_port(tmpctx, "[::1]", &ip, &port));
	assert(streq(ip, "::1"));
	assert(port == 0);

	// service names not supported yet
	assert(!separate_address_and_port(tmpctx, "[::1]:http", &ip, &port));

	// localhost hostnames for backward compat
	assert(parse_wireaddr("localhost", &addr, 200, NULL));
	assert(addr.port == 200);

	// string should win the port battle
	assert(parse_wireaddr("[::1]:9735", &addr, 500, NULL));
	assert(addr.port == 9735);
	ip = fmt_wireaddr(tmpctx, &addr);
	assert(streq(ip, "[::1]:9735"));

	// should use argument if we have no port in string
	assert(parse_wireaddr("2001:db8:85a3::8a2e:370:7334", &addr, 9777, NULL));
	assert(addr.port == 9777);

	ip = fmt_wireaddr(tmpctx, &addr);
	assert(streq(ip, "[2001:db8:85a3::8a2e:370:7334]:9777"));

	assert(parse_wireaddr("[::ffff:127.0.0.1]:49150", &addr, 1, NULL));
	assert(addr.port == 49150);

  assert(parse_wireaddr("4ruvswpqec5i2gogopxl4vm5bruzknbvbylov2awbo4rxiq4cimdldad.onion:49150", &addr, 1, NULL));
	assert(addr.port == 49150);

	assert(parse_wireaddr("4ruvswpqec5i2gogopxl4vm5bruzknbvbylov2awbo4rxiq4cimdldad.onion", &addr, 1, NULL));
	assert(addr.port == 1);

	assert(parse_wireaddr("odpzvneidqdf5hdq.onion:49150", &addr, 1, NULL));
	assert(addr.port == 49150);

	assert(parse_wireaddr("odpzvneidqdf5hdq.onion", &addr, 1, NULL));
	assert(addr.port == 1);
	tal_free(tmpctx);
	return 0;
}

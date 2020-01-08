#include <ccan/io/io.h>
#include <ccan/short_types/short_types.h>
#include <ccan/tal/str/str.h>
#include <common/status.h>
#include <common/utils.h>
#include <common/wireaddr.h>
#include <connectd/connectd.h>
#include <connectd/tor.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define SOCKS_NOAUTH		0
#define SOCKS_ERROR 	 0xff
#define SOCKS_CONNECT		1
#define SOCKS_TYP_IPV4		1
#define SOCKS_DOMAIN		3
#define SOCKS_TYP_IPV6		4
#define SOCKS_V5            5

#define MAX_SIZE_OF_SOCKS5_REQ_OR_RESP 255
#define SIZE_OF_RESPONSE 		4
#define SIZE_OF_REQUEST 		3
#define SIZE_OF_IPV4_RESPONSE 	6
#define SIZE_OF_IPV6_RESPONSE 	18
#define SOCK_REQ_METH_LEN		3
#define SOCK_REQ_V5_LEN			5
#define SOCK_REQ_V5_HEADER_LEN	7

/* some crufts can not forward ipv6*/
#undef BIND_FIRST_TO_IPV6

static char *for_most_humans_readable_tor_socks5_response(const tal_t *ctx, u8 return_code)
{
	switch (return_code) {
		case 0x00:
			return tal_strdup(ctx, "Connection is not accepted");
		case 0x01:
			return tal_strdup(ctx, "General SOCKS server failure");
		case 0x02:
			return tal_strdup(ctx, "Connection not allowed by ruleset");
		case 0x03:
			return tal_strdup(ctx, "Network is unreachable");
		case 0x04:
			return tal_strdup(ctx, "Host is unreachable");
		case 0x05:
			return tal_strdup(ctx, "Connection is refused");
		case 0x06:
			return tal_strdup(ctx, "TTL has expired");
		case 0x07:
			return tal_strdup(ctx, "Command is not supported");
		case 0x08:
			return tal_strdup(ctx, "Address type is not supported");
		default:
		/* opps we wish to never read this in the logs */
			return tal_strdup(ctx, "Unknown error");
	}
}

struct connecting_socks {
	u8 buffer[MAX_SIZE_OF_SOCKS5_REQ_OR_RESP];
	size_t hlen;
	in_port_t port;
	char *host;
	struct connecting *connect;
};

static struct io_plan *connect_finish2(struct io_conn *conn,
				       struct connecting_socks *connect)
{
	status_io(LOG_IO_IN, NULL, "proxy",
		  connect->buffer + SIZE_OF_RESPONSE + SIZE_OF_IPV4_RESPONSE,
		  SIZE_OF_IPV6_RESPONSE - SIZE_OF_IPV4_RESPONSE);
	status_debug("Now try LN connect out for host %s", connect->host);
	return connection_out(conn, connect->connect);
}

static struct io_plan *connect_finish(struct io_conn *conn,
				      struct connecting_socks *connect)
{
	status_io(LOG_IO_IN, NULL, "proxy",
		  connect->buffer, SIZE_OF_IPV4_RESPONSE + SIZE_OF_RESPONSE);

	if ( connect->buffer[1] == '\0') {
		if ( connect->buffer[3] == SOCKS_TYP_IPV6) {
			/* Read rest of response */
			return io_read(conn,
				       connect->buffer + SIZE_OF_RESPONSE +
				       SIZE_OF_IPV4_RESPONSE,
				       SIZE_OF_IPV6_RESPONSE -
				       SIZE_OF_IPV4_RESPONSE,
				       &connect_finish2, connect);

		} else if ( connect->buffer[3] == SOCKS_TYP_IPV4) {
			status_debug("Now try LN connect out for host %s",
				     connect->host);
			return connection_out(conn, connect->connect);
		} else {
			/* Even tor socks code states can this ever happen?
			 * at least dump the hex return code to logs
			*/
			status_debug
			    ("Tor connect out for host %s error ignored response invalid response type %0x returned",
			     connect->host,
			     connect->buffer[3]);
			/* Since we do not write any more, we do not need to sync_flush to consume bytes
			 * we just close
			*/
			return io_close(conn);
		}
	} else {
		/* The tor socks5 proxy returned an error dump the errorcode and readable string */
		status_debug("Tor connect out for host %s error: %0x - %s",
			     connect->host,
			     connect->buffer[1],
			     for_most_humans_readable_tor_socks5_response(tmpctx, connect->buffer[1]));
		return io_close(conn);
	}
}

/* called when TOR responds */
static struct io_plan *connect_out(struct io_conn *conn,
				   struct connecting_socks *connect)
{
	return io_read(conn, connect->buffer,
		       SIZE_OF_IPV4_RESPONSE + SIZE_OF_RESPONSE,
		       &connect_finish, connect);

}

static struct io_plan *io_tor_connect_after_resp_to_connect(struct io_conn
							    *conn,
							    struct
							    connecting_socks
							    *connect)
{
	status_io(LOG_IO_IN, NULL, "proxy", connect->buffer, 2);

	if (connect->buffer[1] == SOCKS_ERROR) {
		status_debug("Connected out for %s error: the tor socks server does not understand our connect method",
			     connect->host);
		return io_close(conn);
	}
	if (connect->buffer[1] == '\0') {
		/* make the V5 request */
		connect->hlen = strlen(connect->host);
		connect->buffer[0] = SOCKS_V5;
		connect->buffer[1] = SOCKS_CONNECT;
		connect->buffer[2] = 0;
		connect->buffer[3] = SOCKS_DOMAIN;
		connect->buffer[4] = connect->hlen;

		memcpy(connect->buffer + SOCK_REQ_V5_LEN, connect->host, connect->hlen);
		memcpy(connect->buffer + SOCK_REQ_V5_LEN + strlen(connect->host),
				&(connect->port), sizeof connect->port);

		status_io(LOG_IO_OUT, NULL, "proxy", connect->buffer,
				SOCK_REQ_V5_HEADER_LEN + connect->hlen);
		return io_write(conn, connect->buffer,
				SOCK_REQ_V5_HEADER_LEN + connect->hlen,
				connect_out, connect);
	} else {
		status_debug("Connected out for %s error: unexpected connect answer %0x from the tor socks5 proxy",
				connect->host,
				connect->buffer[1]);
		return io_close(conn);
	}
}

static struct io_plan *io_tor_connect_after_req_to_connect(struct io_conn *conn,
							   struct connecting_socks
							   *connect)
{
	return io_read(conn, connect->buffer, 2,
		       &io_tor_connect_after_resp_to_connect, connect);
}

static struct io_plan *io_tor_connect_do_req(struct io_conn *conn,
					     struct connecting_socks *connect)
{
	/* make the init request */
	connect->buffer[0] = SOCKS_V5;
	connect->buffer[1] = 1;
	connect->buffer[2] = SOCKS_NOAUTH;

	status_io(LOG_IO_OUT, NULL, "proxy", connect->buffer, SOCK_REQ_METH_LEN);
	return io_write(conn, connect->buffer, SOCK_REQ_METH_LEN,
			&io_tor_connect_after_req_to_connect, connect);
}

// called when we want to connect to TOR SOCKS5
struct io_plan *io_tor_connect(struct io_conn *conn,
			       const struct addrinfo *tor_proxyaddr,
			       const char *host, u16 port,
			       struct connecting *connect)
{
	struct connecting_socks *connect_tor = tal(connect,
						   struct connecting_socks);

	connect_tor->port = htons(port);
	connect_tor->host = tal_strdup(connect_tor, host);
	connect_tor->connect = connect;

	return io_connect(conn, tor_proxyaddr,
			  &io_tor_connect_do_req, connect_tor);
}

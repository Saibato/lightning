#include <common/base64.h>
#include <sodium.h>
#include <sodium/utils.h>

char *b64_encode(const tal_t *ctx, char *data, size_t len)
{
	char *str = tal_arrz(ctx, char, sodium_base64_encoded_len(len, sodium_base64_VARIANT_ORIGINAL) + 1);

	str = sodium_bin2base64(str,  tal_count(str), (const unsigned char *)data,
								len, sodium_base64_VARIANT_ORIGINAL);
	return str;
}

char *b64_decode(const tal_t *ctx, char *str, size_t len)
{
	char *ret = tal_arrz(ctx, char, strlen(str) + 1);
	const char *b64_end;

	if (!sodium_base642bin((unsigned char * const )ret,
				tal_count(ret),
				(const char * const)str,
				len,
				NULL,
				NULL,
				&b64_end,
				sodium_base64_VARIANT_ORIGINAL))
			return tal_free(ret);

	return ret;
}

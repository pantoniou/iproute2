#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <linux/unet.h>

#include "utils.h"

static const char *hex = "0123456789abcdef";

static inline bool is_valid_ua_addr_char(const char c)
{
	return c  > ' ' && c <= '~' &&
	       c != ':' && c != '/' && c != '.' && c != '$';
}

static char *unet_addr_to_str(const struct unet_addr *ua)
{
	int i, len, alloclen;
	char c;
	char *d, *str;
	const __u8 *s;
	bool use_hex;

	if (!ua)
		return NULL;

	/*
	 * if the whole address is ascii with non of [~:/.$]
	 * then output as address as a string
	 */
	len = unet_addr_buffer_len(ua);
	s = ua->addr_buffer;
	for (i = 0; i < len; i++) {
		c = *s++;
		if (!is_valid_ua_addr_char(c))
			break;
	}

	use_hex = i < len;

	if (use_hex)
		alloclen = len * 2 + 5; /* $.:.\0 */
	else
		alloclen = len + 4;     /* .:.\0 */

	str = malloc(alloclen);
	if (!str)
		return NULL;
	d = str;
	s = ua->addr_buffer;	/* laid out in sequence, utilize */

	if (use_hex)
		*d++ = '$';

#undef OUTPUT_CHUNK
#define OUTPUT_CHUNK(_l) \
	do { \
		len = (_l); \
		for (i = 0; i < len; i++) { \
			c = *s++; \
			if (!use_hex) \
				*d++ = c; \
			else { \
				*d++ = hex[((unsigned int)c >> 4) & 15]; \
				*d++ = hex[ (unsigned int)c       & 15]; \
			} \
		} \
	} while(0)

	if (ua->parent_prefix_len && ua->parent_id_len) {
		OUTPUT_CHUNK(ua->parent_prefix_len);
		*d++ = '.';
		OUTPUT_CHUNK(ua->parent_id_len);
		*d++ = ':';
	}
	OUTPUT_CHUNK(ua->prefix_len);
	*d++ = '.';
	OUTPUT_CHUNK(ua->id_len);
	*d = '\0';

#undef OUTPUT_CHUNK
	return str;
}

static int unet_str_to_addr(const char *str, int size, struct unet_addr *ua)
{
	const char *s, *se;
	__u8 *d;
	int dots, colons;
	const char *dotsp[2];
	const char *colonp;
	char c;
	bool is_hex;

	if (size == -1)
		size = strlen(str);
	while (size > 0 && isspace(str[size-1]))
		size--;
	se = str + size;

	if (size <= 1) {
		errno = EINVAL;
		return -1;
	}

	/* hex address? */
	if (*str == '$') {
		str++;
		is_hex = true;
	} else
		is_hex = false;

	dotsp[0] = dotsp[1] = NULL;
	colonp = NULL;

	dots = 0;
	colons = 0;
	for (s = str; s < se; s++) {
		c = *s;
		if (c == '.') {
			/* no more than 2 dots */
			if (dots > 1) {
				errno = EINVAL;
				return -1;
			}
			/* second dot must be preceded by a colon */
			if (dots == 1 && colons == 0) {
				errno = EINVAL;
				return -1;
			}
			dotsp[dots++] = s;
		} else if (c == ':') {
			/* no more than 1 colon */
			if (colons > 0) {
				errno = EINVAL;
				return -1;
			}
			/* we must have encountered a dot already */
			if (dots == 0) {
				errno = EINVAL;
				return -1;
			}
			colonp = s;
			colons++;
		} else if (is_hex) {
			/* hex-address and is not a hex digit */
			if (!isxdigit(c) && !isdigit(c)) {
				errno = EINVAL;
				return -1;
			}
		} else {
			/* if it's not a valid addr */
			if (!is_valid_ua_addr_char(c)) {
				errno = EINVAL;
				return -1;
			}
		}
	}

	/* at least one dot must be present (prefix is mandatory) */
	if (dots == 0) {
		errno = EINVAL;
		return -1;
	}

	/* we have a valid address string */
	s = str;
	d = ua->addr_buffer;

#undef CONVERT_CHUNK
#define CONVERT_CHUNK(_len) \
	({	\
		int len = (_len); \
		__u8 *ds = d; \
		__u8 v; \
		while (len > 0) { \
			if (is_hex) { \
				/* there must be two bytes at least */ \
				if (len < 2) { \
	 				errno = EINVAL; \
					return -1; \
	 			} \
				c = *s++; \
				if (c >= '0' && c <= '9') \
					v = c - '0'; \
				else \
					v = 10 + (tolower(c) - 'a'); \
				v <<= 4; \
				c = *s++; \
				if (c >= '0' && c <= '9') \
					v |= c - '0'; \
				else \
					v |= 10 + (tolower(c) - 'a'); \
				len -= 2; \
			} else { \
				v = *s++; \
				len--; \
			} \
			*d++ = v; \
		} \
		d - ds; \
	})

	/* we have a parent type address */
	dots = 0;
	if (colonp) {
		ua->parent_prefix_len = CONVERT_CHUNK(dotsp[dots] - s);
		s++;
		ua->parent_id_len = CONVERT_CHUNK(colonp - s);
		s++;
		dots++;
	} else {
		ua->parent_prefix_len = 0;
		ua->parent_id_len = 0;
	}
	ua->prefix_len = CONVERT_CHUNK(dotsp[dots] - s);
	s++;
	ua->id_len = CONVERT_CHUNK(se - s);

#undef CONVERT_CHUNK
	return 0;
}

static const char *unet_ntop1(const struct unet_addr *ua, char *buf, size_t buflen)
{
	char *str;

	str = unet_addr_to_str(ua);
	if (!str) {
		errno = -EINVAL;
		return NULL;
	}

	if (strlen(str) + 1 > buflen) {
		free(str);
		errno = -E2BIG;
		return NULL;
	}
	strncpy(buf, str, buflen - 1);
	free(str);
	return buf;
}

const char *unet_ntop(int af, const void *addr, char *buf, size_t buflen)
{
	switch(af) {
	case AF_UNET:
		errno = 0;
		return unet_ntop1(addr, buf, buflen);
	default:
		errno = EAFNOSUPPORT;
	}

	return NULL;
}

static int unet_pton1(const char *name, struct unet_addr *ua)
{
	int err;

	err = unet_str_to_addr(name, -1, ua);
	if (err)
		return err;

	/* all OK */
	return 1;
}

int unet_pton(int af, const char *src, void *addr)
{
	int err;

	switch(af) {
	case AF_UNET:
		errno = 0;
		err = unet_pton1(src, addr);
		break;
	default:
		errno = EAFNOSUPPORT;
		err = -1;
	}

	return err;
}

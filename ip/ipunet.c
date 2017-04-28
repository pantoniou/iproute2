/*
 * iptunnel.c	       "ip unet"
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Pantelis Antoniou <pantelis.antoniou@konsulko.com>
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/unet.h>
#include <pwd.h>
#include <grp.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <glob.h>

#include "rt_names.h"
#include "utils.h"
#include "ip_common.h"

#define UNET_CFS	"/config/unet"
#define UNET_ENTITY_CFS	 UNET_CFS "/entities"

static void usage(void) __attribute__((noreturn));

static void usage(void)
{
	fprintf(stderr, "Usage: ip unet { add | del | show | list | lst | trustchain | help }\n");
	fprintf(stderr, "          [ name NAME ]\n");
	fprintf(stderr, "\n");
	exit(-1);
}

/* safe values */
#define CERT_MAX_SIZE		16384
#define PRIV_KEY_MAX_SIZE	8192

struct unet_parm {
	char name[IFNAMSIZ];
	struct unet_addr addr;
	struct unet_addr force_parent;
	unsigned int dev_class;
	bool can_be_router;
	unsigned int cert_size;
	__u8 cert[CERT_MAX_SIZE];
	unsigned int privkey_size;
	__u8 privkey[PRIV_KEY_MAX_SIZE];
};

static int parse_args(int argc, char **argv, struct unet_parm *p)
{
	int count = 0;
	ssize_t len;
	int fd;

	memset(p, 0, sizeof(*p));

	while (argc > 0) {
		if (strcmp(*argv, "can-be-router") == 0 ||
		    strcmp(*argv, "can_be_router") == 0) {
			p->can_be_router = true;
		} else if (strcmp(*argv, "dev-class") == 0 ||
			   strcmp(*argv, "dev_class") == 0 ||
			   strcmp(*argv, "class") == 0) {
			NEXT_ARG();
			p->dev_class = atoi(*argv);
		} else if (strcmp(*argv, "cert") == 0) {
			NEXT_ARG();
			fd = open(*argv, O_RDONLY);
			if (fd < 0) {
				fprintf(stderr, "failed to open cert %s\n", *argv);
				return -1;
			}
			len = read(fd, p->cert, sizeof(p->cert));
			close(fd);
			if (len < 0 || len >= sizeof(p->cert)) {
				fprintf(stderr, "failed to read cert %s\n", *argv);
				return -1;
			}
			p->cert_size = len;
		} else if (strcmp(*argv, "privkey") == 0) {
			NEXT_ARG();
			fd = open(*argv, O_RDONLY);
			if (fd < 0) {
				fprintf(stderr, "failed to open privkey %s\n", *argv);
				return -1;
			}
			len = read(fd, p->privkey, sizeof(p->privkey));
			close(fd);
			if (len < 0 || len >= sizeof(p->privkey)) {
				fprintf(stderr, "failed to read privkey %s\n", *argv);
				return -1;
			}
			p->privkey_size = len;
		} else if (strcmp(*argv, "force-parent") == 0 ||
			   strcmp(*argv, "force_parent") == 0) {
			NEXT_ARG();
			if (unet_pton(AF_UNET, *argv, &p->force_parent) <= 0) {
				fprintf(stderr, "failed on force parent %s\n", *argv);
				return -1;
			}
		} else if (strcmp(*argv, "name") == 0) {
			NEXT_ARG();
			strncpy(p->name, *argv, IFNAMSIZ - 1);
		} else {
			if (strcmp(*argv, "addr") == 0)
				NEXT_ARG();
			else if (matches(*argv, "help") == 0)
				usage();

			if (unet_pton(AF_UNET, *argv, &p->addr) <= 0) {
				fprintf(stderr, "failed on addr %s\n", *argv);
				return -1;
			}

		}
		count++;
		argc--; argv++;
	}

	if (!unet_addr_is_valid(&p->addr)) {
		fprintf(stderr, "no address given\n");
		return -1;
	}

	return 0;
}

#if 0
static void dump_parm(struct unet_parm *p)
{
	char buf[1024];

	if (p->name[0])
		fprintf(stderr, "%-20s = %s\n", "name", p->name);
	
	fprintf(stderr, "%-20s = %s\n", "addr",
			unet_ntop(AF_UNET, &p->addr, buf, sizeof(buf)));

	if (unet_addr_is_valid(&p->force_parent))
		fprintf(stderr, "%-20s = %s\n", "force-parent",
				unet_ntop(AF_UNET, &p->force_parent, buf, sizeof(buf)));

	if (p->cert_size > 0)
		fprintf(stderr, "%-20s = %u\n", "cert-size", p->cert_size);

	if (p->privkey_size > 0)
		fprintf(stderr, "%-20s = %u\n", "privkey-size", p->privkey_size);
}
#endif

static int write_config(const char *base, const char *prop, void *data, int size)
{
	char filename[PATH_MAX];
	int fd, len;

	len = snprintf(filename, sizeof(filename), "%s/%s", base, prop);
	if (len >= sizeof(filename) - 1)
		return -1;

	fd = open(filename, O_WRONLY);
	if (fd == -1)
		return -1;

	len = write(fd, data, size);
	close(fd);

	if (len != size)
		return -1;
	return 0;
}

static int write_config_int(const char *base, const char *prop, int what)
{
	char buf[16];

	snprintf(buf, sizeof(buf), "%d\n", what);
	return write_config(base, prop, buf, strlen(buf));
}

static int write_config_str(const char *base, const char *prop, const char *str)
{
	char buf[4096];

	snprintf(buf, sizeof(buf), "%s\n", str);
	return write_config(base, prop, buf, strlen(str));
}

static int unet_add(struct unet_parm *p)
{
	char addrstr[1024], forceparentstr[1024];
	char dirname[PATH_MAX];
	int len;

	if (!unet_ntop(AF_UNET, &p->addr, addrstr, sizeof(addrstr))) {
		fprintf(stderr, "unet: error on ntop\n");
		return -1;
	}
	len = snprintf(dirname, sizeof(dirname), "/config/unet/entities/%s", addrstr);
	if (len >= sizeof(dirname) - 1) {
		fprintf(stderr, "unet: path larger than PATH_MAX\n");
		return -1;
	}

	if (mkdir(dirname, S_IRWXU)) {
		fprintf(stderr, "unet: failed to create dir\n");
		return -1;
	}

	write_config_int(dirname, "dev_class", p->dev_class);
	write_config_int(dirname, "can_be_router", p->can_be_router);
	if (unet_addr_is_valid(&p->force_parent)) {
		if (!unet_ntop(AF_UNET, &p->force_parent, forceparentstr,
			       sizeof(forceparentstr))) {
			fprintf(stderr, "unet: error on ntop\n");
			return -1;
		}
		write_config_str(dirname, "force_parent", forceparentstr);
	}
	if (p->cert_size > 0)
		write_config(dirname, "cert", p->cert, p->cert_size);
	if (p->privkey_size > 0)
		write_config(dirname, "privkey", p->privkey, p->privkey_size);

	write_config_int(dirname, "enable", 1);

	return 0;
}

static int unet_del(struct unet_parm *p)
{
	char addrstr[1024];
	char dirname[PATH_MAX];
	int len;

	if (!unet_ntop(AF_UNET, &p->addr, addrstr, sizeof(addrstr))) {
		fprintf(stderr, "unet: error on ntop\n");
		return -1;
	}
	len = snprintf(dirname, sizeof(dirname), "/config/unet/entities/%s", addrstr);
	if (len >= sizeof(dirname) - 1) {
		fprintf(stderr, "unet: path larger than PATH_MAX\n");
		return -1;
	}
	if (rmdir(dirname)) {
		fprintf(stderr, "unet: rmdir failed\n");
		return -1;
	}

	return 0;
}

static int do_add(int argc, char **argv)
{
	struct unet_parm up;

	if (parse_args(argc, argv, &up) < 0)
		return -1;

	return unet_add(&up);
}

static int do_del(int argc, char **argv)
{
	struct unet_parm up;

	if (parse_args(argc, argv, &up) < 0)
		return -1;

	return unet_del(&up);
}

static int do_show(int argc, char **argv)
{
	fprintf(stderr, "%s\n", __func__);
	return 0;
}

static int do_trustchain(int argc, char **argv)
{
	return 0;
}

int do_ipunet(int argc, char **argv)
{
	if (argc > 0) {
		if (matches(*argv, "add") == 0)
			return do_add(argc-1, argv+1);
		if (matches(*argv, "delete") == 0)
			return do_del(argc-1, argv+1);
		if (matches(*argv, "show") == 0 ||
		    matches(*argv, "lst") == 0 ||
		    matches(*argv, "list") == 0)
			return do_show(argc-1, argv+1);
		if (matches(*argv, "trustchain") == 0)
			return do_trustchain(argc-1, argv+1);
		if (matches(*argv, "help") == 0)
			usage();
	} else
		return do_show(0, NULL);

	fprintf(stderr, "Command \"%s\" is unknown, try \"ip unet help\".\n",
		*argv);
	exit(-1);
}

/* link commands */

static void print_explain(FILE *f)
{
	fprintf(f,
		"Usage: ... unet [ local-entity UNET_ADDR ]\n"
		"                [ remote-entity UNET_ADDR ]\n"
		"                [ remote IP_ADDRESS ]\n"
		"                [ local ADDR ]\n"
		"\n"
		"Where: ADDR  := IP_ADDRESS\n"
	);
}

static void explain(void)
{
	print_explain(stderr);
}

static int unet_parse_opt(struct link_util *lu, int argc, char **argv,
			  struct nlmsghdr *n)
{
	__u32 local_addr = 0;
	__u32 remote_addr = 0;
	struct unet_addr local_entity_addr, remote_entity_addr;
	struct in6_addr addr6 = IN6ADDR_ANY_INIT;

	memset(&local_entity_addr, 0, sizeof(local_entity_addr));
	memset(&remote_entity_addr, 0, sizeof(remote_entity_addr));

	while (argc > 0) {
		if (!matches(*argv, "remote")) {
			NEXT_ARG();
			if (!inet_get_addr(*argv, &remote_addr, &addr6) || 
			    remote_addr == INADDR_ANY || IN_MULTICAST(ntohl(local_addr)))
				invarg("invalid remote address", *argv);
		} else if (!matches(*argv, "local")) {
			NEXT_ARG();
			if (!inet_get_addr(*argv, &local_addr, &addr6) || 
			    IN_MULTICAST(ntohl(local_addr)))
				invarg("invalid local address", *argv);
		} else if (!matches(*argv, "local-entity")) {
			NEXT_ARG();
			if (unet_pton(AF_UNET, *argv, &local_entity_addr) <= 0)
				invarg("invalid local entity address", *argv);
		} else if (!matches(*argv, "remote-entity")) {
			NEXT_ARG();
			if (unet_pton(AF_UNET, *argv, &remote_entity_addr) <= 0)
				invarg("invalid remote entity address", *argv);
		} else if (matches(*argv, "help") == 0) {
			explain();
			return -1;
		} else {
			fprintf(stderr, "unet: unknown command \"%s\"?\n", *argv);
			explain();
			return -1;
		}
		argc--, argv++;
	}

	if (unet_addr_is_valid(&local_entity_addr))
		addattr_l(n, 1024, IFLA_UNET_LOCAL_ENTITY, &local_entity_addr,
				sizeof(struct unet_addr));
	if (unet_addr_is_valid(&remote_entity_addr))
		addattr_l(n, 1024, IFLA_UNET_REMOTE_ENTITY, &remote_entity_addr,
				sizeof(struct unet_addr));
	if (local_addr)
		addattr_l(n, 1024, IFLA_UNET_LOCAL, &local_addr, 4);
	if (remote_addr)
		addattr_l(n, 1024, IFLA_UNET_REMOTE, &remote_addr, 4);

	return 0;
}

static void unet_print_opt(struct link_util *lu, FILE *f, struct rtattr *tb[])
{
	struct unet_addr *ua;
	char buf[1024];
	__be32 addr;

	if (!tb)
		return;

	if (tb[IFLA_UNET_LOCAL_ENTITY]) {
		ua = RTA_DATA(tb[IFLA_UNET_LOCAL_ENTITY]);
		if (unet_addr_is_valid(ua))
			fprintf(f, "local-entity %s ",
				unet_ntop(AF_UNET, ua, buf, sizeof(buf)));
	}

	if (tb[IFLA_UNET_REMOTE_ENTITY]) {
		ua = RTA_DATA(tb[IFLA_UNET_REMOTE_ENTITY]);
		if (unet_addr_is_valid(ua))
			fprintf(f, "remote-entity %s ",
				unet_ntop(AF_UNET, ua, buf, sizeof(buf)));
	}

	if (tb[IFLA_UNET_LOCAL]) {
		addr = rta_getattr_u32(tb[IFLA_UNET_LOCAL]);
		fprintf(f, "local %s ", format_host(AF_INET, 4, &addr));
	}

	if (tb[IFLA_UNET_REMOTE]) {
		addr = rta_getattr_u32(tb[IFLA_UNET_REMOTE]);
		fprintf(f, "remote %s ", format_host(AF_INET, 4, &addr));
	}
}

static void unet_print_help(struct link_util *lu, int argc, char **argv,
	FILE *f)
{
	print_explain(f);
}

struct link_util unet_link_util = {
	.id		= "unet",
	.maxattr	= IFLA_UNET_MAX,
	.parse_opt	= unet_parse_opt,
	.print_opt	= unet_print_opt,
	.print_help	= unet_print_help,
};

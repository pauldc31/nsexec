#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <libnl3/netlink/route/link.h>
#include <libnl3/netlink/route/link/veth.h>

static int int_pid;

static struct nl_sock *sk;
static struct nl_cache *cache;
static struct rtnl_link *link;

static void usage()
{
	fprintf(stderr, "Usage:\n"
			"\tnsexec_nic create pid hostVETH containerVETH\n"
			"\tnsexec_nic delete hostVETH\n");
	exit(EXIT_FAILURE);
}


static void create_veth(const char *veth_host, const char *veth_ns)
{
	struct rtnl_link *change, *bridge;
	int err;

	sk = nl_socket_alloc();
	err = nl_connect(sk, NETLINK_ROUTE);
	if (err < 0) {
		fprintf(stderr, "Error: Unable to connect to netlink route: %s\n",
				nl_geterror(err));
		exit(EXIT_FAILURE);
	}

	err = rtnl_link_veth_add(sk, veth_host, veth_ns, int_pid);
	if (err < 0) {
		fprintf(stderr, "Error: Unable to create veth pair: %s\n",
				nl_geterror(err));
		exit(EXIT_FAILURE);
	}

	err = rtnl_link_alloc_cache(sk, AF_UNSPEC, &cache);
	if (err < 0) {
		fprintf(stderr, "Error: Unable to allocate cache: %s\n",
				nl_geterror(err));
		exit(EXIT_FAILURE);
	}

	link = rtnl_link_get_by_name(cache, veth_host);
	if (!link) {
		fprintf(stderr, "Error: Unable to find1: %s\n", veth_host);
		exit(EXIT_FAILURE);
	}

	bridge = rtnl_link_get_by_name(cache, "virbr0");
	if (!bridge) {
		fprintf(stderr, "Error: Unable to find virbr0\n");
		exit(EXIT_FAILURE);
	}

	err = rtnl_link_enslave(sk, bridge, link);
	if (err < 0) {
		fprintf(stderr, "Error: could not enslave %s into virbr0: %s\b",
				veth_host, nl_geterror(err));
		exit(EXIT_FAILURE);
	}

	change = rtnl_link_alloc();
	rtnl_link_set_flags(change, IFF_UP);

	err = rtnl_link_change(sk, link, change, 0);
	if (err < 0) {
		fprintf(stderr, "Error: Unable to activate %s: %s\n",
				veth_host, nl_geterror(err));
		exit(EXIT_FAILURE);
	}

	nl_close(sk);
}

static void delete_veth(const char *veth_host)
{
	int err;

	sk = nl_socket_alloc();
	err = nl_connect(sk, NETLINK_ROUTE);
	if (err < 0) {
		fprintf(stderr, "Error: Unable to connect to netlink route: %s\n",
				nl_geterror(err));
		exit(EXIT_FAILURE);
	}

	err = rtnl_link_alloc_cache(sk, AF_UNSPEC, &cache);
	if (err < 0) {
		fprintf(stderr, "Error: Unable to allocate cache: %s\n",
				nl_geterror(err));
		exit(EXIT_FAILURE);
	}

	link = rtnl_link_get_by_name(cache, veth_host);
	if (!link) {
		fprintf(stderr, "Error: delete: Unable to find2: %s\n", veth_host);
		exit(EXIT_FAILURE);
	}

	err = rtnl_link_delete(sk, link);
	if (err < 0) {
		fprintf(stderr, "Error: Unable to delete: %s\n", veth_host);
		exit(EXIT_FAILURE);
	}

	nl_close(sk);
}

int main(int argc, char **argv)
{
	int ret;
	if (argc < 3)
		usage();

	if (!strncmp(argv[1], "create", 6)) {
		if (argc < 5)
			usage();

		ret = sscanf(argv[2], "%d", &int_pid);
		if (ret != 1) {
			fprintf(stderr, "Invalid pid\n");
			exit(EXIT_FAILURE);
		}

		create_veth(argv[3], argv[4]);
	} else if (!strncmp(argv[1], "delete", 6)) {
		delete_veth(argv[2]);
	} else {
		usage();
	}

	return 0;
}

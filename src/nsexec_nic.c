#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <libnl3/netlink/route/link.h>
#include <libnl3/netlink/route/link/veth.h>

static int int_pid;
static char veth_name[15];

static struct nl_sock *sk;
static struct nl_cache *cache;
static struct rtnl_link *link;

static void usage()
{
	fprintf(stderr, "Usage: <create|delete> pid\n");
	exit(EXIT_FAILURE);
}

static int convert_pid(char *pid)
{
	int local_pid;
	if (sscanf(pid, "%d", &local_pid) != 1)
		return -1;

	return local_pid;
}

static void create_veth(void)
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

	err = rtnl_link_veth_add(sk, veth_name, "eth0", int_pid);
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

	link = rtnl_link_get_by_name(cache, veth_name);
	if (!link) {
		fprintf(stderr, "Error: Unable to find: %s\n", veth_name);
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
				veth_name, nl_geterror(err));
		exit(EXIT_FAILURE);
	}

	change = rtnl_link_alloc();
	rtnl_link_set_flags(change, IFF_UP);

	err = rtnl_link_change(sk, link, change, 0);
	if (err < 0) {
		fprintf(stderr, "Error: Unable to activate %s: %s\n",
				veth_name, nl_geterror(err));
		exit(EXIT_FAILURE);
	}

	nl_close(sk);
}

static void delete_veth()
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

	link = rtnl_link_get_by_name(cache, veth_name);
	if (!link) {
		fprintf(stderr, "Error: delete: Unable to find: %s\n", veth_name);
		exit(EXIT_FAILURE);
	}

	err = rtnl_link_delete(sk, link);
	if (err < 0) {
		fprintf(stderr, "Error: Unable to delete: %s\n", veth_name);
		exit(EXIT_FAILURE);
	}

	nl_close(sk);
}

int main(int argc, char **argv)
{
	if (argc < 3)
		usage();

	int_pid = convert_pid(argv[2]);
	if (int_pid == -1) {
		fprintf(stderr, "Invalid pid\n");
		exit(EXIT_FAILURE);
	}

	if (snprintf(veth_name, sizeof(veth_name), "veth%s", argv[2]) < 0) {
		fprintf(stderr, "Error when setting veth name\n");
		exit(EXIT_FAILURE);
	}

	if (!strncmp(argv[1], "create", 6)) {
		create_veth();
	} else if (!strncmp(argv[1], "delete", 6)) {
		delete_veth();
	} else {
		usage();
	}

	return 0;
}

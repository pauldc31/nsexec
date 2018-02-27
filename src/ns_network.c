#include <err.h>
#include <netlink/netlink.h>
#include <netlink/route/addr.h>
#include <netlink/route/link.h>
#include <netlink/route/route.h>
#include <net/if.h> /* IFF_UP */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <uuid/uuid.h>

enum {
	CREATE_BRIDGE,
	DELETE_BRIDGE
};

void setup_veth_names(char *veth_h, char *veth_ns)
{
	static uuid_t gen_uuid;
	char uuid_parsed[37];

	uuid_generate_random(gen_uuid);
	uuid_unparse_upper(gen_uuid, uuid_parsed);

	/* copy just the first foud characters from uuid for veth_h */
	if (snprintf(veth_h, 9, "veth%s", uuid_parsed) < 0)
		err(EXIT_FAILURE, "building veth_h");

	/* copy the next four characters from the start of the uuid */
	if (snprintf(veth_ns, 9, "veth%s", uuid_parsed + 4) < 0)
		err(EXIT_FAILURE, "building veth_ns");
}

void setup_container_network(char *veth_ns)
{
	struct nl_sock *sk;
	struct rtnl_link *link, *eth, *change;
	struct nl_cache *cache;
	struct nl_addr *addr;
	struct rtnl_addr *rt_addr;
	struct rtnl_route *route;
	struct rtnl_nexthop *nh;
	int ifindex;
	int err;

	sk = nl_socket_alloc();
	err = nl_connect(sk, NETLINK_ROUTE);
	if (err < 0)
		errx(EXIT_FAILURE, "Error: Unable to connect netlink route: %s"
				, nl_geterror(err));

	err = rtnl_link_alloc_cache(sk, AF_UNSPEC, &cache);
	if (err < 0)
		errx(EXIT_FAILURE, "Error: Unable to build link cache: %s",
				nl_geterror(err));

	link = rtnl_link_get_by_name(cache, "lo");
	if (!link)
		errx(EXIT_FAILURE, "Error: Could not find loopback interface");

	change = rtnl_link_alloc();
	rtnl_link_set_flags(change, IFF_UP);

	err = rtnl_link_change(sk, link, change, 0);
	if (err < 0)
		errx(EXIT_FAILURE, "Error: Unable to activate loopback: %s",
				nl_geterror(err));

	eth = rtnl_link_get_by_name(cache, veth_ns);
	if (!eth)
		errx(EXIT_FAILURE, "Error: Unable to find %s", veth_ns);

	/* rename veth_ns to eth0 inside the ns */
	rtnl_link_set_name(change, "eth0");

	err = rtnl_link_change(sk, eth, change, 0);
	if (err < 0)
		errx(EXIT_FAILURE, "Error: Unable to activate/rename %s to "
				"eth0: %s", veth_ns, nl_geterror(err));

	err = nl_cache_refill(sk, cache);
	if (err < 0)
		errx(EXIT_FAILURE, "Error: Unable to refill cache: %s",
				nl_geterror(err));

	rt_addr = rtnl_addr_alloc();

	err = nl_addr_parse("192.168.122.111/24", AF_INET, &addr);
	if (err < 0)
		errx(EXIT_FAILURE, "Error: Unable to parse IPv4: %s",
				nl_geterror(err));

	ifindex = rtnl_link_name2i(cache, "eth0");
	if (ifindex == 0)
		errx(EXIT_FAILURE, "Error: could not find eth0 index");

	rtnl_addr_set_ifindex(rt_addr, ifindex);
	rtnl_addr_set_local(rt_addr, addr);
	rtnl_addr_set_family(rt_addr, AF_INET);

	err = nl_addr_parse("192.168.122.255", AF_INET, &addr);
	if (err < 0)
		errx(EXIT_FAILURE, "Error: Unable to parse IPv4: %s",
				nl_geterror(err));

	rtnl_addr_set_broadcast(rt_addr, addr);

	err = rtnl_addr_add(sk, rt_addr, 0);
	if (err < 0)
		errx(EXIT_FAILURE, "Error: Unable add address: %s",
				nl_geterror(err));

	nh = rtnl_route_nh_alloc();
	rtnl_route_nh_set_ifindex(nh, ifindex);

	err = nl_addr_parse("192.168.122.1", AF_INET, &addr);
	if (err < 0)
		errx(EXIT_FAILURE, "Error: Unable to parse IPv4: %s",
				nl_geterror(err));

	rtnl_route_nh_set_gateway(nh, addr);

	route = rtnl_route_alloc();
	rtnl_route_set_iif(route, AF_INET);
	rtnl_route_set_scope(route, RT_SCOPE_UNIVERSE);
	rtnl_route_set_table(route, RT_TABLE_MAIN);
	rtnl_route_set_protocol(route, RTPROT_BOOT);
	rtnl_route_set_priority(route, 0);
	rtnl_route_set_type(route, RTN_UNICAST);
	rtnl_route_add_nexthop(route, nh);

	err = nl_addr_parse("default", AF_INET, &addr);
	if (err < 0)
		errx(EXIT_FAILURE, "Error: Unable to parse IPv4 dst: %s",
				nl_geterror(err));

	err = rtnl_route_set_dst(route, addr);
	if (err < 0)
		errx(EXIT_FAILURE, "Error: could not set route dst: %s",
				nl_geterror(err));

	err = rtnl_route_add(sk, route, 0);
	if (err < 0)
		errx(EXIT_FAILURE, "Error: could not add route: %s",
				nl_geterror(err));

	nl_close(sk);
}

static void setup_bridge(int child_pid, int op, char *veth_h, char *veth_ns)
{
	pid_t pid;
	char *binpath = "/usr/bin/nsexec_nic";
	char strpid[15];
	int wstatus;

	pid = fork();
	switch (pid) {
	case -1:
		err(EXIT_FAILURE, "setup_bridge: fork bridge");
		/* fall-thru */
	case 0:
		if (snprintf(strpid, sizeof(strpid), "%d", child_pid) < 0)
			err(EXIT_FAILURE, "setup_bridge: strnpid child_pid");
		if (op == CREATE_BRIDGE)
			execlp(binpath, binpath, "create", strpid, veth_h,
					veth_ns, NULL);
		else if (op == DELETE_BRIDGE)
			execlp(binpath, binpath, "delete", veth_h, NULL);

		errx(EXIT_FAILURE, "execlp bridge failed");
		/* fall-thru */
	default:
		if (waitpid(pid, &wstatus, 0) == -1)
			err(EXIT_FAILURE, "waitpid bridge");

		if (WEXITSTATUS(wstatus))
			err(EXIT_FAILURE, "bridge proc terminated anormally");
	}
}

void create_bridge(int child_pid, char* veth_h, char* veth_ns)
{
	setup_bridge(child_pid, CREATE_BRIDGE, veth_h, veth_ns);
}

void delete_bridge(int child_pid, char *veth_h)
{
	setup_bridge(child_pid, DELETE_BRIDGE, veth_h, NULL);
}

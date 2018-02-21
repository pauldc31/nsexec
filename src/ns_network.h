void setup_container_network(char *veth_ns);
void create_bridge(int child_pid, char* veth_h, char* veth_ns);
void delete_bridge(int child_pid, char *veth_h);

void setup_veth_names(char *veth_h, char *veth_ns);

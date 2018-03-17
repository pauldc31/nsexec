void setup_mountns(struct NS_ARGS *ns_args);
void set_maps(int pid, const char *map, int ns_user, int ns_group);
void handle_mount_opts(struct NS_ARGS *args, char *str_mount, MOUNT_FLAG flag);

void basic_setup(struct NS_ARGS *ns_args);
void setup_mountns(struct NS_ARGS *ns_args);
void setup_rootfs(struct NS_ARGS *ns_args);
void set_maps(int pid, const char *map, struct NS_ARGS *ns_args);
void set_newuid_maps(int pid);
void handle_mount_opts(struct MOUNT_LIST **ml, char *str_mount, MOUNT_FLAG flag);

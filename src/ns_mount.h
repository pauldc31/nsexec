void setup_mountns(struct NS_ARGS *ns_args);
void set_maps(int pid, const char *map, struct NS_ARGS *ns_args);
void handle_mount_opts(struct MOUNT_LIST **ml, char *str_mount, MOUNT_FLAG flag);

# Eswitch configuration script

The eswitch configuration requires the use of devlink and ethtool.

Unfortunately, the only netlink tools currently advanced enough to actually manage the job is `iproute2`, which means this part (tragically) needs to be in bash.

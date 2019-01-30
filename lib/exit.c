
#include <inc/lib.h>

void
exit(int ret)
{
	close_all();
	sys_env_destroy(0, ret);
}


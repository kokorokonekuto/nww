## nww
A small header library to write build scripts.

## Example
```c
/* For copy_file_range() on Linux and FreeBSD. */
#define _GNU_SOURCE
#include <stdio.h>

#include "nww.h"

int main(void)
{
        nww_do_execute("cc", "simple.c", "-o", "simple");
	    return (0);
}
```
See the `examples` directory for more information.

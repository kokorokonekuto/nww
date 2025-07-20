#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>

#define NWW_IMPL
#include "../nww.h"

struct c_files_obj {
        const char *src;
	const char *out;
};

/* TODO: array size */
static void exec_rustc(const char *src, const char *out,
		       const char *obj_files)
{
	char *buf;

	buf = calloc(1024, sizeof(char));
	sprintf(buf,
		"rustc -g --edition 2021 -C opt-level=0 -C panic=abort -C link-args=\"%s\" ",
        	obj_files);
	sprintf(buf + strlen(buf), "%s -o %s -lc", src, out);

	nww_do_log_info(0, stdout, "%s\n", buf);
	/* execute it via sh. */
	nww_do_exec_shell("sh", buf);
	free(buf);
}

static char *format_cc_calls(const char *src, const char *out)
{
	char *buf;

	buf = calloc(1024, sizeof(char));
	sprintf(buf, "cc -fPIC -g -c %s -o %s -lc -lgcc", src, out);
	return (buf);
}

static const struct c_files_obj c_objs[] = {
	{ .src = "thirdparty/nob.c", .out = "build/nob.posix.o" },
	{ .src = "thirdparty/flag.c", .out = "build/flag.posix.o" },
	{ .src = "thirdparty/glob.c", .out = "build/glob.posix.o" },
	{ .src = "thirdparty/libc.c", .out = "build/libc.posix.o" },
	{ .src = "thirdparty/arena.c", .out = "build/arena.posix.o" },
	{ .src = "thirdparty/fake6502.c", .out = "build/fake6502.posix.o" },
	{ .src = "thirdparty/jim.c", .out = "build/jim.posix.o" },
	{ .src = "thirdparty/jimp.c", .out = "build/jimp.posix.o" },
};

static const char *rust_objs[] = {
	"src/arena.rs", "src/b.rs", "src/ir.rs", "src/crust.rs",
	"src/flag.rs", "src/glob.rs", "src/lexer.rs", "src/nob.rs",
	"src/targets.rs", "src/jim.rs", "src/jimp.rs",
	"src/codegen/gas_aarch64.rs", "src/codegen/gas_x86_64.rs",
	"src/codegen/mos6502.rs", "src/codegen/uxn.rs", "src/codegen/mod.rs",
	"src/runner/gas_x86_64_linux.rs", "src/runner/gas_x86_64_windows.rs",
	"src/runner/gas_x86_64_darwin.rs", "src/runner/gas_aarch64_linux.rs",
	"src/runner/gas_aarch64_darwin.rs", "src/runner/mod.rs",
	"src/runner/mos6502.rs", "src/runner/uxn.rs",
};

int main(int argc, char **argv)
{
	int i, recompile;
	struct nww_nono nono;
	char *buf;
	char path[PATH_MAX];

	/* if (argc >= 2 && strcmp(argv[1], "recompile") == 0) */

	/* To make example smaller. */
	/* recompile = (argc < 2) == 0; */
	/* recompile = (argc >= 2) && strcmp(argv[1], "recompile") == 0; */

	if (!nww_do_is_dir("b") && !nww_do_is_dir("libb")) {
		nww_do_exec_shell(
			"sh", "git clone https://github.com/tsoding/b && cd b && "
			"git checkout 79abcd9b0d913f95b8d343388b8b2e9310a9e118");
		snprintf(path, sizeof(path), "b/%s", argv[0]);
		nww_do_copy_file(argv[0], path);
		nww_do_copy_file("nww_b.c", "b/nww_b.c");
	        /* TODO: rm file */
		nww_do_log_trace(0, stdout,
				 "done: now execute %s in the b directory\n", argv[0]);
		unlink(argv[0]);
		return (0);
	}

	recompile = 0;
	if (argc >= 2) {
		if (strcmp(argv[1], "clean") == 0) {
			nww_do_log_ok(0, stdout, "cleared build directory\n");
			nww_do_rm_rec_all("./build");
			return (0);
		} else if (strcmp(argv[1], "recompile") == 0)
			recompile = 1;
		else
			return (-1);
	}

	/* Create a directory if we don't have already. */
	if (!nww_do_is_dir("build"))
	    nww_do_makedir_p("build", 0777);

	for (i = 0; i < nww_do_static_array_size(c_objs); i++) {
		if (recompile || nww_do_has_modified(c_objs[i].src, c_objs[i].out)) {
			buf = format_cc_calls(c_objs[i].src, c_objs[i].out);
			nww_do_log_info(0, stdout, "%s\n", buf);
			nww_do_execute_cstr(buf);
			free(buf);
		}
        }

	/* Check for any changes. */
	for (i = 0; i < nww_do_static_array_size(c_objs); i++) {
		if (nww_do_has_modified(c_objs[i].src, c_objs[i].out))
			recompile = 1;
	}

	for (i = 0; i < nww_do_static_array_size(rust_objs); i++) {
	        if (nww_do_has_modified(rust_objs[i], "build/b") ||
		    nww_do_has_modified(rust_objs[i], "build/btest"))
			recompile = 1;
	}

	if (nww_do_has_modified("src/btest.rs", "build/btest"))
		recompile = 1;

	nww_nono_do_init(&nono);
	for (i = 0; i < nww_do_static_array_size(c_objs); i++) {
		if (recompile) {
			nww_nono_do_push_back(&nono, c_objs[i].out);
			nww_nono_do_push_back(&nono, " ");
		}
	}
	nww_nono_do_finish(&nono);

	if (recompile) {
		exec_rustc("src/b.rs", "build/b", nono.p);
		exec_rustc("src/btest.rs", "build/btest", nono.p);
	}

	nww_nono_do_free(&nono);
}

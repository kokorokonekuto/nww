#ifndef NWW_H
# define NWW_H

#if defined (__linux__)
# ifndef _GNU_SOURCE
#  define _GNU_SOURCE
# endif
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <err.h>
#include <time.h>
#include <fts.h>
#include <signal.h>
#include <limits.h>

struct nww_vv {
	char **p;
	size_t nelems;
	size_t total_elems;
};

struct nww_nono {
	char *p;
	size_t used_size;
	size_t npre_alloc;
};

/* Dynamic array */
void nww_vv_do_init(struct nww_vv *vv);
void nww_vv_do_push_back(struct nww_vv *vv, const char *elem);
void nww_vv_do_free(struct nww_vv *vv);

/* Dynamic string */
void nww_nono_do_init(struct nww_nono *nono);
void nww_nono_do_push_back(struct nww_nono *nono, const char *arg);
void nww_nono_do_finish(struct nww_nono *nono);
void nww_nono_do_free(struct nww_nono *nono);

/* Execution */
void nww_private_do_execute(int nargs, ...);
void nww_private_do_execute_stype(struct nww_vv *vv);
void nww_private_do_execute_cstr_p(struct nww_nono *nono);
void nww_private_do_execute_cstr(const char *args);
void nww_private_do_exec_shell(const char *shell, const char *args);

int nww_private_do_has_modified(const char *src, const char *obj);

/* Logging */
void nww_private_do_log_type(unsigned int show_time, unsigned int log_type,
			     FILE *out, const char *fmt, ...);

/* File types */
int nww_private_do_is_file_obj(const char *path, int file_type);
int nww_private_do_is_file_obj_any(const char *path);

/* Utils */
void nww_private_do_makedir(const char *path, mode_t mode);
void nww_private_do_makedir_p(const char *path, mode_t mode);
void nww_private_do_rm_empty_dir(const char *path);
void nww_private_do_rm_rec_all(const char *path);
void nww_private_do_rm_file(const char *path);
void nww_private_do_copy_file(const char *src, const char *dst);
void nww_private_do_copy_dir_rec(const char *src, const char *dst);
void nww_private_do_copy_dirp_only(const char *dpath);

/* Collect the number of arguments.
   https://stackoverflow.com/a/2124433 */
#define NWW_NARGS(...) (sizeof((char *[]){__VA_ARGS__})/sizeof(char *))

/* Execution functions */
#define nww_do_execute(...)						\
	nww_private_do_execute(NWW_NARGS(__VA_ARGS__), __VA_ARGS__)
#define nww_do_execute_stype(vv)		\
	nww_private_do_execute_stype(vv)
#define nww_do_execute_cstr(args)		\
	nww_private_do_execute_cstr(args)
#define nww_do_execute_cstr_stype(nono)		\
	nww_private_do_execute_cstr_p(nono)
#define nww_do_exec_shell(shell, args)		\
	nww_private_do_exec_shell(shell, args)

/* Directory/File functions */
#define nww_do_makedir(path, mode)		\
	nww_private_do_makedir(path, mode)
#define nww_do_makedir_p(path, mode)		\
	nww_private_do_makedir_p(path, mode)
#define nww_do_rm_empty_dir(path)		\
        nww_private_do_rm_empty_dir(path)
#define nww_do_rm_rec_all(path)			\
	nww_private_do_rm_rec_all(path)
#define nww_do_rm_file(path)			\
	nww_private_do_rm_file(path)

/* Files type */
#define nww_do_is_file(path)				\
	nww_private_do_is_file_obj(path, S_IFREG)
#define nww_do_is_dir(path)				\
	nww_private_do_is_file_obj(path, S_IFDIR)
#define nww_do_is_chr(path)				\
	nww_private_do_is_file_obj(path, S_IFCHR)
#define nww_do_is_blk(path)				\
	nww_private_do_is_file_obj(path, S_IFBLK)
#define nww_do_is_fifo(path)				\
	nww_private_do_is_file_obj(path, S_IFIFO)
#define nww_do_is_lnk(path)				\
	nww_private_do_is_file_obj(path, S_IFLNK)
#define nww_do_is_sock(path)				\
	nww_private_do_is_file_obj(path, S_IFSOCK)
#define nww_do_is_file_any(path)		\
	nww_private_do_is_file_any(path)

/* Misc */
#define nww_do_static_array_size(arr)    sizeof(arr)/sizeof(*arr)
#define nww_do_copy_file(src, dst)		\
	nww_private_do_copy_file(src, dst)
#define nww_do_copy_dir_rec(src, dst)		\
	nww_private_do_copy_dir_rec(src, dst)
#define nww_do_copy_dirp_only(dpath)		\
	nww_private_do_copy_dirp_only(dpath)
#define nww_do_has_modified(src, obj)		\
	nww_private_do_has_modified(src, obj)

/* vv */
#define nww_vv_do_init(vv)			\
	nww_private_vv_do_init(vv)
#define nww_vv_do_push_back(vv, elem)		\
	nww_private_vv_do_push_back(vv, elem)
#define nww_vv_do_free(vv)			\
	nww_private_vv_do_free(vv)

/* nono */
#define nww_nono_do_init(nono)			\
	nww_private_nono_do_init(nono)
#define nww_nono_do_push_back(nono, value)		\
	nww_private_nono_do_push_back(nono, value)
#define nww_nono_do_finish(nono)		\
	nww_private_nono_do_finish(nono)
#define nww_nono_do_free(nono)			\
	nww_private_nono_do_free(nono)

/* Logging functions */

#define NWW_TYPE_LOG_TRACE       1
#define NWW_TYPE_LOG_OK          2
#define NWW_TYPE_LOG_INFO        3
#define NWW_TYPE_LOG_WARN        4
#define NWW_TYPE_LOG_ERROR       5
#define NWW_TYPE_LOG_CONFIG      6
#define NWW_TYPE_LOG_SEVERE      7

#define NWW_TYPE_COLOR_RED       (char *)"\x1b[1;91m"
#define NWW_TYPE_COLOR_GREEN     (char *)"\x1b[1;92m"
#define NWW_TYPE_COLOR_YELLOW    (char *)"\x1b[1;93m"
#define NWW_TYPE_COLOR_BLUE      (char *)"\x1b[1;94m"
#define NWW_TYPE_COLOR_VIOLET    (char *)"\x1b[1;95m"
#define NWW_TYPE_COLOR_CYAN      (char *)"\x1b[1;96m"
#define NWW_TYPE_COLOR_WHITE     (char *)"\x1b[1;97m"
#define NWW_TYPE_COLOR_END        (char *)"\x1b[0m"
#define NWW_TYPE_STYLE_ITALIC             (char *)"\x1b[3m"
#define NWW_TYPE_STYLE_UNDERLINE          (char *)"\x1b[4m"
#define NWW_TYPE_STYLE_BLINK              (char *)"\x1b[5m"
#define NWW_TYPE_STYLE_INVERT             (char *)"\x1b[7m"
#define NWW_TYPE_STYLE_STRIKETHROUGH      (char *)"\x1b[9m"

#define nww_do_log_trace(show_time, out, ...)				\
	nww_private_do_log_type(show_time, NWW_TYPE_LOG_TRACE, out, __VA_ARGS__)
#define nww_do_log_ok(show_time, out, ...)				\
	nww_private_do_log_type(show_time, NWW_TYPE_LOG_OK, out, __VA_ARGS__)
#define nww_do_log_info(show_time, out, ...)				\
	nww_private_do_log_type(show_time, NWW_TYPE_LOG_INFO, out, __VA_ARGS__)
#define nww_do_log_warn(show_time, out, ...)				\
	nww_private_do_log_type(show_time, NWW_TYPE_LOG_WARN, out, __VA_ARGS__)
#define nww_do_log_error(show_time, out, ...)				\
	nww_private_do_log_type(show_time, NWW_TYPE_LOG_ERROR, out, __VA_ARGS__)
#define nww_do_log_config(show_time, out, ...)				\
	nww_private_do_log_type(show_time, NWW_TYPE_LOG_CONFIG, out, __VA_ARGS__)
#define nww_do_log_severe(show_time, out, ...)				\
	nww_private_do_log_type(show_time, NWW_TYPE_LOG_SEVERE, out, __VA_ARGS__)

/* #define NWW_IMPL */
#ifdef NWW_IMPL

/* Dynamic arraylist. */
void nww_private_vv_do_init(struct nww_vv *vv)
{
	if ((vv->p = (char **)calloc(1, sizeof(char *))) == NULL)
	        abort();
	vv->nelems = 0;
	vv->total_elems = 0;
}

void nww_private_vv_do_push_back(struct nww_vv *vv, const char *elem)
{
	if ((vv->p = (char **)realloc(vv->p, vv->total_elems +
				      sizeof(char *))) == NULL)
		abort();

	vv->p[vv->nelems++] = (char *)elem;
	vv->total_elems += sizeof(char *);
}

void nww_private_vv_do_free(struct nww_vv *vv)
{
	free(vv->p);
	vv->nelems = 0;
	vv->total_elems = 0;
}

/* Dynamic string. */
void nww_private_nono_do_init(struct nww_nono *nono)
{
	if ((nono->p = (char *)calloc(1, sizeof(char))) == NULL)
		abort();
	nono->used_size = nono->npre_alloc = 0;
}

void nww_private_nono_do_push_back(struct nww_nono *nono, const char *arg)
{
	size_t len;

	len = strlen(arg);
allocate_chunk:
	/* used_size 1000 999 (used)
	   len 999 */
	if (len >= nono->used_size || nono->npre_alloc <= nono->used_size) { 
		nono->npre_alloc = (nono->used_size + len) * 2;
		if ((nono->p = (char *)realloc(nono->p, nono->npre_alloc + 1)) == NULL)
			abort();
	} else {
		nono->npre_alloc -= len;
		if (nono->npre_alloc <= nono->used_size)
			goto allocate_chunk;
	}

	memcpy(nono->p + nono->used_size, arg, len);
	nono->used_size += len;
}

void nww_private_nono_do_push_back_wl(struct nww_nono *nono,
				      const char *arg, size_t len)
{
allocate_again:
        if (len >= nono->used_size || nono->npre_alloc <= nono->used_size) {
		nono->npre_alloc = (nono->used_size + len) * 2;
		if ((nono->p = (char *)realloc(nono->p, nono->npre_alloc
					       + 1)) == NULL)
			abort();
	} else {
		if (len > nono->npre_alloc)
		        goto allocate_again;
		nono->npre_alloc -= len;
	}

	memcpy(nono->p + nono->used_size, arg, len);
	nono->used_size += len;
}

void nww_private_nono_do_finish(struct nww_nono *nono)
{
        *(nono->p + nono->used_size) = '\0';
}

void nww_private_nono_do_free(struct nww_nono *nono)
{
	free(nono->p);
	nono->npre_alloc = 0;
	nono->used_size = 0;
}

/* Execution functions. */
void nww_private_do_execute(int nargs, ...)
{
	int ret;
	struct nww_vv vv;
	va_list ap;
	pid_t pid;

	nww_vv_do_init(&vv);

        va_start(ap, nargs);
        while (nargs-- > 0)
		nww_vv_do_push_back(&vv, va_arg(ap, char *));

	va_end(ap);

	/* Mark as end the list of arguments. */
	nww_vv_do_push_back(&vv, NULL);
	pid = fork();
	/* Execute a child process from the fork. */
        if (pid == 0) {
		ret = execvp(vv.p[0], vv.p);
		if (!ret)
			while (waitpid(pid, NULL, 0) < 0 && errno == EINTR)
				;
	}

	nww_vv_do_free(&vv);
}

void nww_private_do_execute_stype(struct nww_vv *vv)
{
	pid_t pid;

	/* Execute a child process from the fork. */
        if ((pid = fork()) == 0) {
	        if (!execvp(vv->p[0], vv->p))
			while (waitpid(pid, NULL, 0) < 0 && errno == EINTR)
				;
	}
}

void nww_private_do_execute_cstr_p(struct nww_nono *nono)
{
	char *tok, *buf;
	struct nww_vv vv;
	pid_t pid;
        
	buf = nono->p;
	nww_vv_do_init(&vv);
        while ((tok = strsep(&buf, " ")) != NULL)
	        nww_vv_do_push_back(&vv, tok);

	nww_vv_do_push_back(&vv, NULL);
	if ((pid = fork()) == 0) {
		if (!execvp(vv.p[0], vv.p))
			while (waitpid(pid, NULL, 0) < 0 && errno == EINTR)
				;
	}

	nww_vv_do_free(&vv);
}

void nww_private_do_execute_cstr(const char *args)
{
	char *tok, *buf;
	struct nww_vv vv;
	struct nww_nono nono;
	pid_t pid;

	nww_nono_do_init(&nono);
	nww_nono_do_push_back(&nono, args);
	nww_nono_do_finish(&nono);

	buf = nono.p;
	nww_vv_do_init(&vv);
        while ((tok = strsep(&buf, " ")) != NULL)
	        nww_vv_do_push_back(&vv, tok);

	nww_vv_do_push_back(&vv, NULL);
	if ((pid = fork()) == 0) {
		if (!execvp(vv.p[0], vv.p))
			while (waitpid(pid, NULL, 0) < 0 && errno == EINTR)
				;
	}

	nww_nono_do_free(&nono);
	nww_vv_do_free(&vv);
}

/* https://github.com/lattera/freebsd/blob/master/lib/libc/stdlib/system.c */
void nww_private_do_exec_shell(const char *shell, const char *args)
{
	pid_t pid;
	char *alist[5];
	sigset_t block, orig;
	struct sigaction sa_ignore, sa_quit, sa_int;

	sigemptyset(&block);
	sigaddset(&block, SIGCHLD);
	sigaddset(&block, SIGINT);
	sigaddset(&block, SIGQUIT);
	sigprocmask(SIG_BLOCK, &block, &orig);

	sa_ignore.sa_handler = SIG_IGN;
	sa_ignore.sa_flags = 0;
	sigemptyset(&sa_ignore.sa_mask);
	sigaction(SIGINT, &sa_ignore, &sa_int);
	sigaction(SIGQUIT, &sa_ignore, &sa_quit);

	alist[0] = (char *)shell;
	alist[1] = (char *)"-c";
	alist[2] = (char *)"--";
	alist[3] = (char *)args;
	alist[4] = NULL;

	pid = vfork();
	switch (pid) {
	case -1:
		sigprocmask(SIG_SETMASK, &orig, NULL);
		err(EXIT_FAILURE, "fork()");
	case 0:
	        execvp(shell, alist);
		_exit(EXIT_FAILURE);
	}

	while (waitpid(pid, NULL, 0) < 0 && errno == EINTR)
		;

	sigprocmask(SIG_SETMASK, &orig, NULL);
	sigaction(SIGINT, &sa_int, NULL);
	sigaction(SIGQUIT, &sa_quit, NULL);
}

int nww_private_do_has_modified(const char *src, const char *obj)
{
	struct stat st0, st1;

	/* Expect obj to not exists, so return a negative value. */
	if (stat(src, &st0) < 0 || stat(obj, &st1) < 0)
	        return (-1);

	/* UNIX timestamp will increment, so we don't have to
	   handle anything else. */
	if (st0.st_mtim.tv_sec == st1.st_mtim.tv_sec)
	        return (st0.st_mtim.tv_nsec > st1.st_mtim.tv_nsec);
	else
		return (st0.st_mtim.tv_sec > st1.st_mtim.tv_sec);
}

void nww_private_do_log_type(unsigned int show_time, unsigned int log_type,
			     FILE *out, const char *fmt, ...)
{
	va_list ap;
	time_t t;
	struct tm *tm;
	char tbuf[200], *msg;

	va_start(ap, fmt);

	if (show_time) {
	        if ((t = time(NULL)) == -1)
			err(EXIT_FAILURE, "time()");
		if ((tm = localtime(&t)) == NULL)
			err(EXIT_FAILURE, "localtime()");

		if (strftime(tbuf, sizeof(tbuf), "%H:%M:%S", tm) == 0)
			err(EXIT_FAILURE, "strftime()");
		fprintf(out, "%s ", tbuf);
	}

	switch (log_type) {
	case NWW_TYPE_LOG_TRACE:
		msg = NWW_TYPE_COLOR_WHITE"(trace):\x1b[0m "; break;
	case NWW_TYPE_LOG_OK:
		msg = NWW_TYPE_COLOR_GREEN"(ok):\x1b[0m "; break;
	case NWW_TYPE_LOG_INFO:
		msg = NWW_TYPE_COLOR_VIOLET"(info):\x1b[0m "; break;
	case NWW_TYPE_LOG_WARN:
		msg = NWW_TYPE_COLOR_YELLOW"(warn):\x1b[0m "; break;
        case NWW_TYPE_LOG_ERROR:
		msg = NWW_TYPE_COLOR_RED"(error):\x1b[0m "; break;
        case NWW_TYPE_LOG_CONFIG:
		msg = NWW_TYPE_COLOR_CYAN"(config):\x1b[0m "; break;
        case NWW_TYPE_LOG_SEVERE:
		msg = NWW_TYPE_COLOR_RED"(severe):\x1b[0m "; break;
        default:
		fputs("error: invalid logging type\n", stderr);
		abort();
	}

	fprintf(out, "%s", msg);
	vfprintf(stdout, fmt, ap);
	va_end(ap);
}

void nww_private_do_makedir(const char *path, mode_t mode)
{
	if (mkdir(path, mode) == -1)
		err(EXIT_FAILURE, "mkdir()");
}

void nww_private_do_makedir_p(const char *path, mode_t mode)
{
	char *tok, *p;
	struct nww_nono nono_p, nono_np;

	nww_nono_do_init(&nono_p);
	nww_nono_do_init(&nono_np);
	nww_nono_do_push_back(&nono_p, path);
	nww_nono_do_finish(&nono_p);

	p = nono_p.p;
	while ((tok = strsep(&p, "/")) != NULL) {
		nww_nono_do_push_back(&nono_np, tok);
		nww_nono_do_finish(&nono_np);
	        if (nono_np.p == NULL)
			abort();
	        if (mkdir(nono_np.p, mode) == -1) {
		        if (errno != EEXIST && errno != ENOENT)
				err(EXIT_FAILURE, "mkdir()");
		}
	        nww_nono_do_push_back(&nono_np, "/");
	}

	nww_nono_do_finish(&nono_np);
        nww_nono_do_free(&nono_p);
	nww_nono_do_free(&nono_np);
}

/* TODO: portable errno */
void nww_private_do_rm_empty_dir(const char *path)
{
	if (rmdir(path) == -1)
		err(EXIT_FAILURE, "rmdir()");
}

void nww_private_do_rm_rec_all(const char *path)
{
	FTS *fts;
	char *args[] = { (char *)path, NULL };
	FTSENT *ent;

	if ((fts = fts_open(args, FTS_NOCHDIR, NULL)) == NULL)
		err(EXIT_FAILURE, "fts_open()");

	while ((ent = fts_read(fts)) != NULL) {
		switch (ent->fts_info) {
		case FTS_F: case FTS_SL: case FTS_SLNONE:			
		        if (unlink(ent->fts_path) == -1)
				err(EXIT_FAILURE, "unlink()");
			break;
		case FTS_DP:
			/* fts_read() visits the directory in both preorder
			   and postorder, FTS_DP, shows the postorder list. */
			if (rmdir(ent->fts_path) == -1)
				err(EXIT_FAILURE, "rmdir()");
			break;
		case FTS_DNR: case FTS_ERR:
			warn("fts_read()");
	        }
	}

	fts_close(fts);
}

void nww_private_do_rm_file(const char *path)
{
	if (unlink(path) == -1)
		err(EXIT_FAILURE, "unlink()");
}

void nww_private_do_copy_file(const char *src, const char *dst)
{
	int sfd, dfd;
        struct stat st;

	if ((sfd = open(src, O_RDONLY)) == -1)
		err(EXIT_FAILURE, "open()");
	if ((dfd = open(dst, O_WRONLY | O_CREAT)) == -1)
		err(EXIT_FAILURE, "open()");

	if (fstat(sfd, &st) == -1)
		err(EXIT_FAILURE, "fstat()");
#if defined (__linux__) || defined (__FreeBSD__)
	if (copy_file_range(sfd, NULL, dfd, NULL, st.st_size, 0) == -1)
		err(EXIT_FAILURE, "copy_file_range()");
#else
	unsigned char buf[10];
	ssize_t bytes;

	memset(buf, '\0', sizeof(buf));
	while ((bytes = read(sfd, buf, sizeof(buf))) > 0)
		write(dfd, buf, bytes);
#endif
	
	/* Retain permissions for the new file. */
	if (fchmod(dfd, st.st_mode) == -1)
		err(EXIT_FAILURE, "fchmod()");
        close(sfd);
	close(dfd);
}

void nww_private_do_copy_dir_rec(const char *src, const char *dst)
{
        FTS *fts;
	FTSENT *ent;
	char *args[] = { (char *)src, NULL };
	char buf[PATH_MAX], *dp;
	struct stat st;

	if ((fts = fts_open(args, FTS_NOCHDIR, NULL)) == NULL)
		err(EXIT_FAILURE, "fts_open()");

	while ((ent = fts_read(fts)) != NULL) {
		switch (ent->fts_info) {
		case FTS_F:
			memset(buf, '\0', sizeof(buf));
			if ((dp = ent->fts_path +
			     strcspn(ent->fts_path, "/")) == NULL)
				*dp = '\0';

			/* Remove trailling '/'. */
			if (*dp == '/')
				dp++;
			snprintf(buf, sizeof(buf), "%s/%s", dst, dp);
		        nww_private_do_copy_file(ent->fts_path, buf);
			fprintf(stdout, "ent->fts_path: %s\n", buf);
			break;
		case FTS_D:
			if (stat(ent->fts_path, &st) == -1)
				err(EXIT_FAILURE, "stat()");

			memset(buf, '\0', sizeof(buf));
		        if ((dp = ent->fts_path +
			     strcspn(ent->fts_path, "/")) == NULL)
				*dp = '\0';

			/* Remove trailling slash '/'. */
			if (*dp == '/')
				dp++;
		        snprintf(buf, sizeof(buf), "%s/%s", dst, dp);
		        nww_private_do_makedir_p(buf, st.st_mode);
			fprintf(stdout, "ent->fts_name (dir): %s\n", ent->fts_path);
			break;
		}
	}
	fts_close(fts);
}

void nww_private_do_copy_dirp_only(const char *dpath)
{	
        nww_private_do_makedir_p(dpath, 0777);
}

int nww_private_do_is_file_obj(const char *path, int file_type)
{
	struct stat st;

	if (stat(path, &st) == -1) {
	        if (file_type == S_IFDIR) {
			if (errno == ENOENT || errno == ENOTDIR)
				return (0);
		} else {
			if (errno == ENOENT)
				return (0);
		}
		err(EXIT_FAILURE, "stat()");
	}

	return ((int)(st.st_mode & S_IFMT) == file_type);
}

int nww_private_do_is_file_obj_any(const char *path)
{
        struct stat st;

	if (stat(path, &st) == -1) {
		if (errno == ENOENT)
			return (0);

		err(EXIT_FAILURE, "stat()");
	}

        switch (st.st_mode & S_IFMT) {
	case S_IFBLK: case S_IFCHR:
	case S_IFDIR: case S_IFIFO:
	case S_IFLNK: case S_IFREG:
	case S_IFSOCK: return (1);
	}

	return (0);
}

#endif /* NWW_IMPL */

#endif /* NWW_H */

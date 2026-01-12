/*****************************************************************************
** Copyright (C) 2015 Brian McGillion.                                      **
**                                                                          **
** Licensed under the Apache License, Version 2.0 (the "License");          **
** you may not use this file except in compliance with the License.         **
** You may obtain a copy of the License at                                  **
**                                                                          **
**      http://www.apache.org/licenses/LICENSE-2.0                          **
**                                                                          **
** Unless required by applicable law or agreed to in writing, software      **
** distributed under the License is distributed on an "AS IS" BASIS,        **
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. **
** See the License for the specific language governing permissions and      **
** limitations under the License.                                           **
*****************************************************************************/

#include "tee_logging.h"

#include "omnishare.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fuse.h>
#include <libgen.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <unistd.h>
#include <utime.h>

#define AES_KEY_SIZE 32 /* in bytes */
#define MAX_PATH_NAME 512
#define KEY_BUF_SIZE 128

/* Persistant config data */
struct om_state {
	char *root_dir;
};

static int recurse_dir(char *parent_dir, uint8_t **key_chain, int *key_count, uint32_t *key_len)
{
	char *tmp_path = strdup(parent_dir);
	char *root_dir = ((struct om_state *)fuse_get_context()->private_data)->root_dir;
	char abs_path[MAX_PATH_NAME] = {0};
	struct stat s_buf;
	int fd;
	int ret = 0;
	uint8_t *tmp_chain = *key_chain;

	/*
	 *  Recurse upto the top of the path so we can build the key chain from
	 */
	if (strcmp(parent_dir, root_dir) != 0) {
		*key_count += 1;
		ret = recurse_dir(dirname(tmp_path), key_chain, key_count, key_len);
	} else {
		return 0;
	}

	/*
	 * Now that we are at the top start collecting all the directory keys in the
	 * hirarachy
	 */

	/* create the path of the new file */
	if (snprintf(abs_path, MAX_PATH_NAME, "%s/%s", parent_dir, ".dirKey") == MAX_PATH_NAME) {
		OT_LOG(LOG_ERR, "Failed to generate, directory key file : %s", strerror(errno));
		goto out;
	}

	if (stat(abs_path, &s_buf) != 0) {
		OT_LOG(LOG_ERR, "Failed to call stat : %s", strerror(errno));
		goto out;
	}

	if (*key_chain == NULL) {
		*key_chain = calloc(*key_count, s_buf.st_size);
		if (!*key_chain) {
			OT_LOG(LOG_ERR, "Failed to calloc : %s", strerror(errno));
			goto out;
		}

		ret = *key_count;
		*key_len = s_buf.st_size;
	}

	fd = open(abs_path, O_RDONLY);
	if (fd < 0) {
		OT_LOG(LOG_ERR, "failed to open : %s", strerror(errno));
		goto out;
	}

	/* make the pointer arithmetic slightly more readable */
	tmp_chain = *key_chain;
	if (read(fd, &tmp_chain[(*key_count - ret) * s_buf.st_size], s_buf.st_size) < 0)
		OT_LOG(LOG_ERR, "failed to read : (%d) %s", errno, strerror(errno));

	close(fd);
out:
	free(tmp_path);
	return ret - 1;
}

static int rewind_path_get_key(char *parent_dir, uint8_t **key_chain, int *key_count,
			       uint32_t *key_len)
{
	char *tmp_path = strdup(parent_dir);
	uint8_t *tmp_keys = NULL;

	*key_count = 0;

	recurse_dir(tmp_path, &tmp_keys, key_count, key_len);

	free(tmp_path);
	*key_chain = tmp_keys;

	return 0;
}

static int generate_dir_key(char *parent_dir, uint8_t *key_buf, uint32_t *key_buf_size)
{
	uint8_t *keychain = NULL;
	int key_count = 0;
	uint32_t key_len = 0;
	int ret;

	if (rewind_path_get_key(parent_dir, &keychain, &key_count, &key_len))
		return -1;

	/*
	 * See if the key_buf is large enough if not et the return value to -1
	 * and update the key_buf_size to the required size
	 */
	if (*key_buf_size < key_len) {
		OT_LOG(LOG_ERR, "Key_buf too small need (%d)", key_len);
		*key_buf_size = key_len;
		return -ENOBUFS;
	}

	ret = omnishare_do_crypto(keychain, key_count, key_len, OM_OP_CREATE_DIRECTORY_KEY, NULL, 0,
				  key_buf, key_buf_size);
	if (ret) {
		OT_LOG(LOG_ERR, "Failed to omnishare_do_crypto : 0x%x", ret);
		return ret;
	}

	return 0;
}

static int enc_dec_file(char *parent_dir, const char *file_buf, uint32_t size, uint8_t op,
			uint8_t *out_dest, uint32_t *out_dest_len)
{
	uint8_t *keychain = NULL;
	int key_count = 0;
	uint32_t key_len = 0;
	int ret;
	uint8_t dest[size + 32];
	uint32_t dest_len = size + 32;

	if (rewind_path_get_key(parent_dir, &keychain, &key_count, &key_len))
		return -1;

	ret = omnishare_do_crypto(keychain, key_count, key_len, op, (uint8_t *)file_buf, size, dest,
				  &dest_len);
	if (ret) {
		OT_LOG(LOG_ERR, "Failed to omnishare_do_crypto : op 0x%x: 0x%x", op, ret);
		return ret;
	}

	if (dest_len > *out_dest_len) {
		OT_LOG(LOG_ERR, "Out buffer too small, requires (%d)", dest_len);
		return -1;
	}

	memcpy(out_dest, dest, dest_len);
	*out_dest_len = dest_len;

	return 0;
}

/*!
 * \brief fixup_lib_path
 * To be useful the lib name should be the whole path so we concatinate the
 * strings here
 * \param path The base directory containing the libraries
 * \param lib_name [IN] The name of the library [OUT] the full path of the
 * library
 * \return 0 on success -1 otherwise
 */
static int fixup_root_path(char *abs_path, const char *path)
{
	char *root_path = ((struct om_state *)fuse_get_context()->private_data)->root_dir;

	if (snprintf(abs_path, MAX_PATH_NAME, "%s%s", root_path, path) == MAX_PATH_NAME) {
		OT_LOG(LOG_ERR, "Failed to expand %s path", path);
		return -1;
	}

	return 0;
}

/*
 * The file system operations:
 */

/** Get file attributes.
 *
 * Similar to stat().  The 'st_dev' and 'st_blksize' fields are
 * ignored.	 The 'st_ino' field is ignored except if the 'use_ino'
 * mount option is given.
 */
int oms_getattr(const char *path, struct stat *buf)
{
	char abs_path[MAX_PATH_NAME] = {0};

	if (fixup_root_path(abs_path, path))
		return -1;

	if (lstat(abs_path, buf)) {
		OT_LOG(LOG_ERR, "Failed to lstat : %s", strerror(errno));
		return -errno;
	}

	/* Report the size of the data section of the file, so omit the encrypted AES
	 * key that is in the top of the file.
	 */
	buf->st_size -= AES_KEY_SIZE;

	return 0;
}

/** Create a directory
 *
 * Note that the mode argument may not have the type specification
 * bits set, i.e. S_ISDIR(mode) can be false.  To obtain the
 * correct directory type bits use  mode|S_IFDIR
 * */
int oms_mkdir(const char *path, mode_t mode)
{
	char abs_path[MAX_PATH_NAME] = {0};
	char dir_key_file[MAX_PATH_NAME] = {0};
	uint8_t key_buf[KEY_BUF_SIZE] = {0};
	uint32_t key_buf_size = sizeof(key_buf);
	int fd, ret;

	OT_LOG(LOG_DEBUG, "%s", path);

	if (fixup_root_path(abs_path, path))
		return -1;

	if (mkdir(abs_path, mode)) {
		OT_LOG(LOG_ERR, "Failed to mkdir : %s", strerror(errno));
		return -errno;
	}

	/* create the path of the new file */
	if (snprintf(dir_key_file, MAX_PATH_NAME, "%s/%s", abs_path, ".dirKey") == MAX_PATH_NAME) {
		OT_LOG(LOG_ERR, "Failed to generate, directory key file : %s", strerror(errno));
		return -errno;
	}

	ret = generate_dir_key(dirname(abs_path), key_buf, &key_buf_size);
	if (ret != 0)
		return -errno;

	/* Create the file and Write out the key */
	fd = creat(dir_key_file, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		OT_LOG(LOG_ERR, "Failed to creat : %s", strerror(errno));
		ret = -errno;
	} else {
		if (write(fd, key_buf, key_buf_size) != key_buf_size) {
			OT_LOG(LOG_ERR, "failed to write : %s", strerror(errno));
			ret = -errno;
		}
	}

	close(fd);

	return ret;
}

/** Remove a file */
int oms_unlink(const char *path)
{
	char abs_path[MAX_PATH_NAME] = {0};

	if (fixup_root_path(abs_path, path))
		return -1;

	if (unlink(abs_path)) {
		OT_LOG(LOG_ERR, "Failed to unlink : %s", strerror(errno));
		return -errno;
	}

	return 0;
}

/** Remove a directory */
int oms_rmdir(const char *path)
{
	char abs_path[MAX_PATH_NAME] = {0};

	if (fixup_root_path(abs_path, path))
		return -1;

	if (rmdir(abs_path)) {
		OT_LOG(LOG_ERR, "Failed to rmdir : %s", strerror(errno));
		return -errno;
	}

	return 0;
}

/** Rename a file */
int oms_rename(const char *oldpath, const char *newpath)
{
	char old_abs_path[MAX_PATH_NAME] = {0};
	char new_abs_path[MAX_PATH_NAME] = {0};

	OT_LOG(LOG_ERR, "rename %s -> %s", oldpath, newpath);

	if (fixup_root_path(old_abs_path, oldpath))
		return -1;

	if (fixup_root_path(new_abs_path, newpath))
		return -1;

	if (rename(old_abs_path, new_abs_path)) {
		OT_LOG(LOG_ERR, "failed to rename : %s", strerror(errno));
		return -errno;
	}

	return 0;
}

/** Change the permission bits of a file */
int oms_chmod(const char *path, mode_t mode)
{
	char abs_path[MAX_PATH_NAME] = {0};

	if (fixup_root_path(abs_path, path))
		return -1;

	if (chmod(abs_path, mode)) {
		OT_LOG(LOG_ERR, "Failed to chmod : %s", strerror(errno));
		return -errno;
	}

	return 0;
}

/** Change the owner and group of a file */
int oms_chown(const char *path, uid_t uid, gid_t gid)
{
	char abs_path[MAX_PATH_NAME] = {0};

	if (fixup_root_path(abs_path, path))
		return -1;

	if (chown(abs_path, uid, gid)) {
		OT_LOG(LOG_ERR, "Failed to chown : %s", strerror(errno));
		return -errno;
	}

	return 0;
}

/** Change the size of a file */
int oms_truncate(const char *path, off_t length)
{
	char abs_path[MAX_PATH_NAME] = {0};

	if (fixup_root_path(abs_path, path))
		return -1;

	if (truncate(abs_path, length)) {
		OT_LOG(LOG_ERR, "Failed to truncate : %s", strerror(errno));
		return -errno;
	}

	return 0;
}

/** File open operation
 *
 * No creation (O_CREAT, O_EXCL) and by default also no
 * truncation (O_TRUNC) flags will be passed to open(). If an
 * application specifies O_TRUNC, fuse first calls truncate()
 * and then open(). Only if 'atomic_o_trunc' has been
 * specified and kernel version is 2.6.24 or later, O_TRUNC is
 * passed on to open.
 *
 * Unless the 'default_permissions' mount option is given,
 * open should check if the operation is permitted for the
 * given flags. Optionally open may also return an arbitrary
 * filehandle in the fuse_file_info structure, which will be
 * passed to all file operations.
 *
 * Changed in version 2.2
 */
int oms_open(const char *path, struct fuse_file_info *info)
{
	int fd;
	char abs_path[MAX_PATH_NAME];

	if (fixup_root_path(abs_path, path))
		return -1;

	fd = open(abs_path, info->flags);
	if (fd < 0) {
		OT_LOG(LOG_ERR, "Failed to open : %s", strerror(errno));
		return -errno;
	}

	info->fh = fd;

	return 0;
}

/** Read data from an open file
 *
 * Read should return exactly the number of bytes requested except
 * on EOF or error, otherwise the rest of the data will be
 * substituted with zeroes.	 An exception to this is when the
 * 'direct_io' mount option is specified, in which case the return
 * value of the read system call will reflect the return value of
 * this operation.
 *
 * Changed in version 2.2
 */
int oms_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *info)
{
	ssize_t ret;
	char abs_path[MAX_PATH_NAME];
	char enc_buf[size];
	uint8_t tmp_dec_buf[size];
	uint32_t tmp_dec_buf_size = size;
	struct stat s_buf;

	if (fixup_root_path(abs_path, path))
		return -1;

	if (stat(abs_path, &s_buf) != 0) {
		OT_LOG(LOG_ERR, "Failed to call stat : %s", strerror(errno));
		return -1;
	}

	ret = pread(info->fh, enc_buf, s_buf.st_size, offset);
	if (ret < 0) {
		OT_LOG(LOG_ERR, "Failed to pread : %s", strerror(errno));
		ret = -errno;
		goto out;
	}

	ret = enc_dec_file(dirname(abs_path), enc_buf, s_buf.st_size, OM_OP_DECRYPT_FILE,
			   tmp_dec_buf, &tmp_dec_buf_size);
	if (ret != 0)
		return -errno;

	memcpy(buf, tmp_dec_buf, tmp_dec_buf_size);

out:
	return size;
}

/** Write data to an open file
 *
 * Write should return exactly the number of bytes requested
 * except on error.	 An exception to this is when the 'direct_io'
 * mount option is specified (see read operation).
 *
 * Changed in version 2.2
 */
int oms_write(const char *path, const char *buf, size_t size, off_t offset,
	      struct fuse_file_info *info)
{
	ssize_t ret;
	char abs_path[MAX_PATH_NAME];
	uint8_t enc_buf[size + AES_KEY_SIZE];
	uint32_t enc_buf_sz = sizeof(enc_buf);

	if (fixup_root_path(abs_path, path))
		return -1;

	ret = enc_dec_file(dirname(abs_path), buf, size, OM_OP_ENCRYPT_FILE, enc_buf, &enc_buf_sz);
	if (ret != 0)
		return -errno;

	ret = pwrite(info->fh, enc_buf, enc_buf_sz, offset);
	if (ret < 0) {
		OT_LOG(LOG_ERR, "Failed to pwrite : %s", strerror(errno));
		return -errno;
	}

	return size;
}

/** Get file system statistics
 *
 * The 'f_frsize', 'f_favail', 'f_fsid' and 'f_flag' fields are ignored
 *
 * Replaced 'struct statfs' parameter with 'struct statvfs' in
 * version 2.5
 */
int oms_statfs(const char *path, struct statvfs *buf)
{
	char abs_path[MAX_PATH_NAME];

	if (fixup_root_path(abs_path, path))
		return -1;

	if (statvfs(abs_path, buf)) {
		OT_LOG(LOG_ERR, "Failed to statvfs : %s", strerror(errno));
		return -errno;
	}

	return 0;
}

/** Possibly flush cached data
 *
 * BIG NOTE: This is not equivalent to fsync().  It's not a
 * request to sync dirty data.
 *
 * Flush is called on each close() of a file descriptor.  So if a
 * filesystem wants to return write errors in close() and the file
 * has cached dirty data, this is a good place to write back data
 * and return any errors.  Since many applications ignore close()
 * errors this is not always useful.
 *
 * NOTE: The flush() method may be called more than once for each
 * open().	This happens if more than one file descriptor refers
 * to an opened file due to dup(), dup2() or fork() calls.	It is
 * not possible to determine if a flush is final, so each flush
 * should be treated equally.  Multiple write-flush sequences are
 * relatively rare, so this shouldn't be a problem.
 *
 * Filesystems shouldn't assume that flush will always be called
 * after some writes, or that if will be called at all.
 *
 * Changed in version 2.2
 */
int oms_flush(const char *path, struct fuse_file_info *info)
{
	OT_LOG(LOG_ERR, "%s : flush %d", path, info->flush);
	return 0;
}

/** Release an open file
 *
 * Release is called when there are no more references to an open
 * file: all file descriptors are closed and all memory mappings
 * are unmapped.
 *
 * For every open() call there will be exactly one release() call
 * with the same flags and file descriptor.	 It is possible to
 * have a file opened more than once, in which case only the last
 * release will mean, that no more reads/writes will happen on the
 * file.  The return value of release is ignored.
 *
 * Changed in version 2.2
 */
int oms_release(const char *path, struct fuse_file_info *info)
{
	if (close(info->fh)) {
		OT_LOG(LOG_ERR, "Failed to close %s : %s", path, strerror(errno));
		return -errno;
	}

	return 0;
}

/** Synchronize file contents
 *
 * If the datasync parameter is non-zero, then only the user data
 * should be flushed, not the meta data.
 *
 * Changed in version 2.2
 */
int oms_fsync(const char *path, int datasync, struct fuse_file_info *info)
{
	int ret = 0;

	if (datasync)
		ret = fdatasync(info->fh);
	else
		ret = fsync(info->fh);

	if (ret) {
		OT_LOG(LOG_ERR, "Failed to fsync %s : %s", path, strerror(errno));
		return -errno;
	}

	return 0;
}

/** Open directory
 *
 * Unless the 'default_permissions' mount option is given,
 * this method should check if opendir is permitted for this
 * directory. Optionally opendir may also return an arbitrary
 * filehandle in the fuse_file_info structure, which will be
 * passed to readdir, closedir and fsyncdir.
 *
 * Introduced in version 2.3
 */
int oms_opendir(const char *path, struct fuse_file_info *info)
{
	DIR *dir;
	char abs_path[MAX_PATH_NAME] = {0};

	if (fixup_root_path(abs_path, path))
		return -1;

	dir = opendir(abs_path);
	if (dir == NULL) {
		OT_LOG(LOG_ERR, "FAIL: opendir : %s", strerror(errno));
		return -errno;
	}

	info->fh = (uint64_t)dir;

	return 0;
}

/** Read directory
 *
 * This supersedes the old getdir() interface.  New applications
 * should use this.
 *
 * The filesystem may choose between two modes of operation:
 *
 * 1) The readdir implementation ignores the offset parameter, and
 * passes zero to the filler function's offset.  The filler
 * function will not return '1' (unless an error happens), so the
 * whole directory is read in a single readdir operation.  This
 * works just like the old getdir() method.
 *
 * 2) The readdir implementation keeps track of the offsets of the
 * directory entries.  It uses the offset parameter and always
 * passes non-zero offset to the filler function.  When the buffer
 * is full (or an error happens) the filler function will return
 * '1'.
 *
 * Introduced in version 2.3
 */
int oms_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset,
		struct fuse_file_info *info)
{
	DIR *dir;
	struct dirent *dent;

	offset = offset;

	dir = (DIR *)info->fh;

	for (dent = readdir(dir); dent != NULL; dent = readdir(dir)) {
		if (filler(buf, dent->d_name, NULL, 0) != 0) {
			OT_LOG(LOG_ERR, "Filler full for path %s", path);
			return -ENOMEM;
		}
	}
	return 0;
}

/** Release directory
 *
 * Introduced in version 2.3
 */
int oms_releasedir(const char *path, struct fuse_file_info *info)
{
	int ret;

	ret = closedir((DIR *)info->fh);
	if (ret)
		OT_LOG(LOG_ERR, "Failed to closedir %s, %s", path, strerror(errno));

	return ret;
}

/**
 * Initialize filesystem
 *
 * The return value will passed in the private_data field of
 * fuse_context to all file operations and as a parameter to the
 * destroy() method.
 *
 * Introduced in version 2.3
 * Changed in version 2.6
 */
void *oms_init(struct fuse_conn_info *info)
{
	char abs_path[MAX_PATH_NAME] = {0};
	char *root_key_file = "/.rootKey";
	struct stat s_buf;
	int fd;
	uint8_t key_buf[4096] = {0};
	uint32_t key_buf_size = sizeof(key_buf);
	int ret, exists;

	OT_LOG(LOG_ERR, "Init with protocol version : Major %d, Minor %d\n", info->proto_major,
	       info->proto_minor);

	if (fixup_root_path(abs_path, root_key_file))
		goto out;

	/* Check to see if the root key file exists, it will not on the first run of
	 * omnishare */
	exists = stat(abs_path, &s_buf);

	fd = open(abs_path, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		OT_LOG(LOG_ERR, "failed to open : %s", strerror(errno));
		goto out;
	}

	if (exists != 0) {
		if (errno == ENOENT) { /* DIRTY, this errno relates to the stat call above */
			/*
			 * We have a new omnishare instance so lets create the root directory key
			 * and store it in the path
			 */
			if (omnishare_generate_root_key(key_buf, &key_buf_size))
				goto out;

			if (write(fd, key_buf, key_buf_size) != key_buf_size) {
				OT_LOG(LOG_ERR, "failed to write : %s", strerror(errno));
				goto fd_out;
			}

		} else {
			/* some other error occured with stat */
			OT_LOG(LOG_ERR, "failed to stat : %s", strerror(errno));
			goto fd_out;
		}

	} else {
		/* root key file already exists so read it from the disk */
		ret = read(fd, key_buf, key_buf_size);
		if (ret < 0) {
			OT_LOG(LOG_ERR, "failed to open : %s", strerror(errno));
			goto fd_out;
		}

		key_buf_size = ret;
	}

	/* Load the root key into the TEE for this omnishare session */
	ret = omnishare_init(key_buf, key_buf_size);
	if (ret)
		OT_LOG(LOG_ERR, "Failed to omnishare_init : 0x%x", ret);

fd_out:
	close(fd);

out:
	return (struct om_state *)fuse_get_context()->private_data;
}

/**
 * Clean up filesystem
 *
 * Called on filesystem exit.
 *
 * Introduced in version 2.3
 */
void oms_destroy(void *data)
{
	struct om_state *state = (struct om_state *)data;

	OT_LOG(LOG_ERR, "Finalizing and freeing %s\n", state->root_dir);

	free(state->root_dir);
	free(state);
}

/**
 * Check file access permissions
 *
 * This will be called for the access() system call.  If the
 * 'default_permissions' mount option is given, this method is not
 * called.
 *
 * This method is not called under Linux kernel versions 2.4.x
 *
 * Introduced in version 2.5
 */
int oms_access(const char *path, int mode)
{
	int ret = 0;
	char abs_path[MAX_PATH_NAME] = {0};

	if (fixup_root_path(abs_path, path))
		return -1;

	ret = access(abs_path, mode);
	if (ret != 0) {
		OT_LOG(LOG_ERR, "Failed to access : %s", strerror(errno));
		ret = -errno;
	}

	return ret;
}

/**
 * Create and open a file
 *
 * If the file does not exist, first create it with the specified
 * mode, and then open it.
 *
 * If this method is not implemented or under Linux kernel
 * versions earlier than 2.6.15, the mknod() and open() methods
 * will be called instead.
 *
 * Introduced in version 2.5
 */
int oms_create(const char *path, mode_t mode, struct fuse_file_info *info)
{
	char abs_path[MAX_PATH_NAME] = {0};
	int fd;

	if (fixup_root_path(abs_path, path))
		return -1;

	fd = creat(abs_path, mode);
	if (fd < 0) {
		OT_LOG(LOG_ERR, "failed to creat : %s", strerror(errno));
		return -errno;
	}

	info->fh = fd;

	return 0;
}

/**
 * Change the size of an open file
 *
 * This method is called instead of the truncate() method if the
 * truncation was invoked from an ftruncate() system call.
 *
 * If this method is not implemented or under Linux kernel
 * versions earlier than 2.6.15, the truncate() method will be
 * called instead.
 *
 * Introduced in version 2.5
 */
int oms_ftruncate(const char *path, off_t length, struct fuse_file_info *info)
{
	if (ftruncate(info->fh, length)) {
		OT_LOG(LOG_ERR, "Failure to ftruncate %s : %s", path, strerror(errno));
		return -errno;
	}

	return 0;
}

/**
 * Get attributes from an open file
 *
 * This method is called instead of the getattr() method if the
 * file information is available.
 *
 * Currently this is only called after the create() method if that
 * is implemented (see above).  Later it may be called for
 * invocations of fstat() too.
 *
 * Introduced in version 2.5
 */
int oms_fgetattr(const char *path, struct stat *buf, struct fuse_file_info *info)
{
	int ret = 0;

	ret = fstat(info->fh, buf);
	if (ret != 0) {
		OT_LOG(LOG_ERR, "Failed to fstat %s: %s", path, strerror(errno));
		return -errno;
	}

	/* Report the size of the data section of the file, so omit the encrypted AES
	 * key that is in the top of the file.
	 */
	buf->st_size -= AES_KEY_SIZE;

	return 0;
}

/**
 * Change the access and modification times of a file with
 * nanosecond resolution
 *
 * This supersedes the old utime() interface.  New applications
 * should use this.
 *
 * See the utimensat(2) man page for details.
 *
 * Introduced in version 2.6
 */

int oms_utimens(const char *path, const struct timespec tv[2])
{
	int ret = 0;
	char abs_path[MAX_PATH_NAME] = {0};

	if (fixup_root_path(abs_path, path))
		return -1;

	/* we use absolute path name, so the dirfd is ignored so pass dummy 0 */
	ret = utimensat(0, abs_path, tv, 0);
	if (ret != 0) {
		OT_LOG(LOG_ERR, "Failed to utimensat: %s", strerror(errno));
		return -errno;
	}

	return 0;
}

/* Fill up the fuse callback struct */
struct fuse_operations oms_operation = {.getattr = oms_getattr,
					.mkdir = oms_mkdir,
					.unlink = oms_unlink,
					.rmdir = oms_rmdir,
					.rename = oms_rename,
					.chmod = oms_chmod,
					.chown = oms_chown,
					.truncate = oms_truncate,
					.open = oms_open,
					.read = oms_read,
					.write = oms_write,
					.statfs = oms_statfs,
					.flush = oms_flush,
					.release = oms_release,
					.fsync = oms_fsync,
					.opendir = oms_opendir,
					.readdir = oms_readdir,
					.releasedir = oms_releasedir,
					.init = oms_init,
					.destroy = oms_destroy,
					.access = oms_access,
					.create = oms_create,
					.ftruncate = oms_ftruncate,
					.fgetattr = oms_fgetattr,
					.utimens = oms_utimens};

void usage(const char *app_name) { printf("Usage: %s <mount_path> <root_path>\n", app_name); }

int main(int argc, char **argv)
{
	struct om_state *state;
	int ret;

	if (argc != 3) {
		usage(argv[0]);
		exit(1);
	}

	state = calloc(1, sizeof(struct om_state));
	if (!state) {
		printf("Failed to allocate state : %s\n", strerror(errno));
		exit(2);
	}

	state->root_dir = realpath(argv[2], NULL);
	argv[2] = NULL;
	argc--;

	printf("starting omnishare FUSE\n");
	ret = fuse_main(argc, argv, &oms_operation, state);
	OT_LOG(LOG_ERR, "Finished omnishare FUSE (%d)\n", ret);

	return ret;
}

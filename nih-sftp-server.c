/*
Copyright (c) 2014-2016, Edward Langley
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name of Edward Langley nor the
      names of its contributors may be used to endorse or promote products
      derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL EDWARD LANGLEY BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

This code originates from http://www.eddylangley.net/nih/sftp/

*/

/* Version 3 SFTP server. Should compile warning-free on most POSIX boxes with:

gcc -O2 -Wall -Wextra -Werror -std=iso9899:1999 -pedantic-errors nih-sftp-server.c -o sftp-server

If not then see "man 7 feature_test_macros". The relevant features are:

_XOPEN_SOURCE for POSIX telldir, seekdir
_XOPEN_SOURCE >=500 for POSIX lstat, telldir, seekdir, readlink, symlink
_XOPEN_SOURCE >=700 for POSIX.1-2008 + XSI fstatat fdopendir; without this 
realpath() is broken and sftp_realpath will return unsupported 
_BSD_SOURCE for futimes; otherwise sftp_fsetstat() will return unsupported
*/
#define _XOPEN_SOURCE 700
#define _BSD_SOURCE
/* GCC folks may prefer to #define _DEFAULT_SOURCE but this is not obviously POSIX compliant */

/* C library */
#include <stdint.h> /* uint32_t */
#include <stdlib.h> /* exit() */
#include <stdio.h> /* fprintf() */
#include <string.h> /* Memmove */
#include <assert.h>
#include <errno.h>  /* errno, EBADF etc */

/* POSIX and friends */
#include <unistd.h> /* Many things */
#include <fcntl.h>  /* O_RDONLY etc */
#include <sys/time.h> /* utimes, futimes */
#include <sys/stat.h> /* f/l/stat/at, chmod */
#include <dirent.h> /* DIR*, readdir and friends */

/* draft-ietf-secsh-filexfer-02 */
#define SSH_FXP_INIT                1
#define SSH_FXP_VERSION             2
#define SSH_FXP_OPEN                3
#define SSH_FXP_CLOSE               4
#define SSH_FXP_READ                5
#define SSH_FXP_WRITE               6
#define SSH_FXP_LSTAT               7
#define SSH_FXP_FSTAT               8
#define SSH_FXP_SETSTAT             9
#define SSH_FXP_FSETSTAT           10
#define SSH_FXP_OPENDIR            11
#define SSH_FXP_READDIR            12
#define SSH_FXP_REMOVE             13
#define SSH_FXP_MKDIR              14
#define SSH_FXP_RMDIR              15
#define SSH_FXP_REALPATH           16
#define SSH_FXP_STAT               17
#define SSH_FXP_RENAME             18
#define SSH_FXP_READLINK           19
#define SSH_FXP_SYMLINK            20
#define SSH_FXP_STATUS            101
#define SSH_FXP_HANDLE            102
#define SSH_FXP_DATA              103
#define SSH_FXP_NAME              104
#define SSH_FXP_ATTRS             105
#define SSH_FXP_EXTENDED          200
#define SSH_FXP_EXTENDED_REPLY    201

#define SSH_FX_OK                            0
#define SSH_FX_EOF                           1
#define SSH_FX_NO_SUCH_FILE                  2
#define SSH_FX_PERMISSION_DENIED             3
#define SSH_FX_FAILURE                       4
#define SSH_FX_BAD_MESSAGE                   5
#define SSH_FX_NO_CONNECTION                 6
#define SSH_FX_CONNECTION_LOST               7
#define SSH_FX_OP_UNSUPPORTED                8

#define SSH_FILEXFER_ATTR_SIZE          0x00000001
#define SSH_FILEXFER_ATTR_UIDGID        0x00000002
#define SSH_FILEXFER_ATTR_PERMISSIONS   0x00000004
#define SSH_FILEXFER_ATTR_ACMODTIME     0x00000008
#define SSH_FILEXFER_ATTR_EXTENDED      0x80000000

#define SSH_FXF_READ            0x00000001
#define SSH_FXF_WRITE           0x00000002
#define SSH_FXF_APPEND          0x00000004
#define SSH_FXF_CREAT           0x00000008
#define SSH_FXF_TRUNC           0x00000010
#define SSH_FXF_EXCL            0x00000020

/* Derived from SFTP specification */
#define MAX_ATTRS_BYTES 32
#define SFTP_PROTOCOL_VERSION 3

/* Defaults */
#define DEFAULT_FILE_PERM 0666
#define DEFAULT_DIR_PERM 0777

/* Implementation limits */
#define MAX_PACKET 34000    /* SFTP: All servers SHOULD support packets of at least 34000 bytes */
#define PERM_MASK 0777
/* Handles are represented as SSH strings; MAX_HANDLE_DIGITS must enable the printing of
MAX_HANDLES in that many digits */
#define MAX_HANDLES 99
#define MAX_HANDLE_DIGITS 2

/* Utility macros */
#define STR(x) #x
#define STREXPAND(x) STR(x)
#define elemof(x) ( sizeof(x) / sizeof( (x)[0] ) )

/* Basic boolean type */
typedef enum
{
    SSH_FALSE = 0,
    SSH_TRUE = 1
} ssh_bool_t;

/* Buffers. There are two buffers - the input buffer, containing 1 SFTP packet,
which we consume as we process the packet, and the output buffer, which we
populate as we reply to the input packet */
typedef struct buff_tag
{
    uint32_t count;     /* Space remaining input pkt/ space left output pkt */
    uint8_t *p_data;    /* Read pointer input pkt/ write ptr output pkt */
    uint8_t data[MAX_PACKET];
} buff_t;

/* We can save the buffer pointers - e.g. to write the rest of the buffer, then
come back and write the length once we know what it is. */
typedef struct buff_save
{
    uint32_t count;     /* Space remaining input pkt/ space left output pkt */
    uint8_t *p_data;    /* Read pointer input pkt/ write ptr output pkt */
} buff_save_t;

/* File attributes */
typedef struct attrs_tag
{
    uint32_t   flags;           /* Which of the following are valid */
    uint32_t   permissions;     /* SSH_FILEXFER_ATTR_PERMISSIONS */
    uint64_t   size;            /* SSH_FILEXFER_ATTR_SIZE */
    uint32_t   uid;             /* SSH_FILEXFER_ATTR_UIDGID */
    uint32_t   gid;             /* SSH_FILEXFER_ATTR_UIDGID */
    uint32_t   atime;           /* SSH_FILEXFER_ATTR_ACMODTIME */
    uint32_t   mtime;           /* SSH_FILEXFER_ATTR_ACMODTIME */
} attrs_t;

/* Handle types. can represent either a file or a directory */
typedef enum handle_use_tag
{
    HANDLE_FREE = 0, /* Zero-initialises to free */
    HANDLE_FILE,
    HANDLE_DIR
} handle_use_t;

typedef struct fxp_handle_tag
{
    handle_use_t use;
    int fd;
    DIR *p_dir;
} fxp_handle_t;

/* Private function prototypes - SFTP */
static void sftp_in(void);
static void sftp_init(void);
static void sftp_open(void);
static void sftp_close(void);
static void sftp_read(void);
static void sftp_write(void);
static void stat_to_attr(struct stat *p_stat, attrs_t *p_attr);
static void do_stat(ssh_bool_t follow_symlinks);
static void sftp_stat(void);
static void sftp_lstat(void);
static void sftp_fstat(void);
static void sftp_setstat(void);
static void sftp_fsetstat(void);
static void sftp_opendir(void);
static void sftp_readdir(void);
static void sftp_remove(void);
static void sftp_mkdir(void);
static void sftp_rmdir(void);
static void sftp_realpath(void);
static void sftp_rename(void);
static void sftp_readlink(void);
static void sftp_symlink(void);

static void read_input(uint32_t len);

/* Buffer pointer save/swap - see typedef comments */
static void buff_save(buff_save_t *p_buff);
static void buff_swap(buff_save_t *p_buff);

/* Various buffer read/write functions. get_* obtains information from (and consumes)
the input buffer, put_* writes to (and consumes space in) the output buffer. It is
always assert()ed that the data to be put_* doesn't overflow the output buffer; cases
where this may occur are very rare by design (e.g. filenames >17k long) */
static void put_status(uint32_t id, uint32_t status);
static void put_handle(uint32_t id, unsigned long handle);
static uint8_t get_byte(void);
static void put_byte(uint8_t data);
/* Not needed static ssh_bool_t get_bool(void);*/
static uint32_t get_uint32(void);
static uint64_t get_uint64(void);
static void put_uint32(uint32_t data);
static void put_uint64(uint64_t data);
static const char *get_string(uint32_t *p_sz_len);
static const uint8_t *get_data(uint32_t *p_len);
static void put_cstring(const char *sz_str);
static fxp_handle_t *get_handle(void);

static void get_attrs(attrs_t *p_attrs);
static void put_attrs(attrs_t *p_attrs);
static void attrs_to_tv(attrs_t *p_attr, struct timeval tv[2]);

/* Portability and POSIX <-> SFTP conversion */
static int pflags_to_unix(uint32_t pflags);
static uint32_t errno_to_sftp(int unix_error);

/* Handle management */
static unsigned long handle_alloc_file(int fd);
static unsigned long handle_alloc_dir(int fd, DIR *p_dir);

/* Private data */
static buff_t ibuff, obuff;
static ssh_bool_t have_init = SSH_FALSE;
static fxp_handle_t handles[MAX_HANDLES];


int main(int argc, char **argv)
{
    (void)argc; /* Unused */
    (void)argv; /* Unused */

    for(;;)
    {
        uint32_t payload_len, packet_len;
        ssize_t temp;
        buff_save_t save;

        /* Read a 4-byte length header into start of packet buffer */
        read_input(4);
        payload_len = get_uint32();

        /* Read the payload into the beginning of the packet buffer overwriting
        length */
        assert(payload_len <= sizeof(ibuff.data));

        /* Read the rest of the packet */
        read_input(payload_len);

        /* We have a whole packet. Each input packet may generate up to one
        output response. Initalise the output buffer with zero length then 
        handle the packet */
        obuff.p_data = obuff.data;
        obuff.count = sizeof(obuff.data);
        buff_save(&save);
        put_uint32(0);
        if (payload_len > 0)
        {
            /* This is a choice - we silently discard zero length input packets */
            sftp_in();
        }

        /* Send response */
        packet_len = sizeof(obuff.data) - obuff.count;
        payload_len = packet_len - 4;
        if (payload_len > 0)
        {
            uint8_t *p_out = obuff.data;

            /* Write length to start of packet */
            buff_swap(&save);
            put_uint32(payload_len);
            while (packet_len > 0)
            {
                fd_set wfds;
                int retval;

                /* Use select() to check the write will succeed just in case our 
                parent process has marked the file descriptor non-blocking */
                FD_ZERO(&wfds);
                FD_SET(STDOUT_FILENO, &wfds);
                retval = select(STDOUT_FILENO + 1, NULL, &wfds, NULL, NULL);
                if (retval == -1)
                {
                    perror("select(stdout)");
                    exit(EXIT_FAILURE);
                }

                temp = write(STDOUT_FILENO, p_out, packet_len);
                if (temp < 0)
                {
                    perror("write()");
                    exit(EXIT_FAILURE);
                }
                p_out += temp;
                packet_len -= temp;
            }
        }
    }
}

static void read_input(uint32_t len)
{
    ssize_t temp;

    /* Initialise input packet */
    ibuff.count = 0;
    ibuff.p_data = ibuff.data;

    /* Read a 4-byte length header */
    while (ibuff.count < len)
    {
        fd_set rfds;
        int retval;

        /* Watch STDIN with select(), just in case our parent process has
        marked it non-blocking */
        FD_ZERO(&rfds);
        FD_SET(STDIN_FILENO, &rfds);
        retval = select(STDIN_FILENO + 1, &rfds, NULL, NULL, NULL);
        if (retval == -1)
        {
            perror("select(stdin)");
            exit(EXIT_FAILURE);
        }

        temp = read(STDIN_FILENO, &ibuff.data[ibuff.count], len - ibuff.count);
        if (temp < 0)
        {
            perror("header read()");
            exit(EXIT_FAILURE);
        }
        else if (temp == 0)
        {
            /* End of file */
            exit(EXIT_SUCCESS);
        }
        ibuff.count += temp;
    }
}

static void sftp_in(void)
{
    /* Obtain the opcode - will fail if zero length packet */
    uint8_t opcode = get_byte();

    /* INIT must be the first packet */
    if (!have_init)
    {
        assert(opcode == SSH_FXP_INIT);
        sftp_init();
        have_init = SSH_TRUE;
        return;
    }
    switch (opcode)
    {
    case SSH_FXP_INIT:
        /* Don't allow INIT more than once */
        fprintf(stderr,"Can't INIT twice\n");
        exit(EXIT_FAILURE);
        break;

    case SSH_FXP_OPEN:
        sftp_open();
        break;

    case SSH_FXP_CLOSE:
        sftp_close();
        break;

    case SSH_FXP_READ:
        sftp_read();
        break;

    case SSH_FXP_WRITE:
        sftp_write();
        break;

    case SSH_FXP_LSTAT:
        sftp_lstat();
        break;

    case SSH_FXP_FSTAT:
        sftp_fstat();
        break;

    case SSH_FXP_SETSTAT:
        sftp_setstat();
        break;

    case SSH_FXP_FSETSTAT:
        sftp_fsetstat();
        break;

    case SSH_FXP_OPENDIR:
        sftp_opendir();
        break;

    case SSH_FXP_READDIR:
        sftp_readdir();
        break;

    case SSH_FXP_REMOVE:
        sftp_remove();
        break;

    case SSH_FXP_MKDIR:
        sftp_mkdir();
        break;

    case SSH_FXP_RMDIR:
        sftp_rmdir();
        break;

    case SSH_FXP_REALPATH:
        sftp_realpath();
        break;

    case SSH_FXP_STAT:
        sftp_stat();
        break;

    case SSH_FXP_RENAME:
        sftp_rename();
        break;

    case SSH_FXP_READLINK:
        sftp_readlink();
        break;

    case SSH_FXP_SYMLINK:
        sftp_symlink();
        break;

    default:
        /* All (non-INIT) packets begin with an ID and all responses echo it */
        put_status(get_uint32(), SSH_FX_OP_UNSUPPORTED);
        break;
    }
}

static void sftp_init(void)
{
    uint32_t version = get_uint32();

    /* For now we'll be version 3 */
    assert(version >= SFTP_PROTOCOL_VERSION);

    /* Reply with our version */
    put_byte(SSH_FXP_VERSION);
    put_uint32(SFTP_PROTOCOL_VERSION);
    /* No extension pairs */
}

static void sftp_open(void)
{
    uint32_t id;
    const char *sz_filename;
    uint32_t pflags;
    attrs_t attrs;
    int fd,flags;
    mode_t mode;
    uint32_t status = SSH_FX_FAILURE;

    /* Read input packet */
    id = get_uint32();
    sz_filename = get_string(NULL);
    pflags = get_uint32();
    get_attrs(&attrs);
    flags = pflags_to_unix(pflags);
    mode = attrs.flags & SSH_FILEXFER_ATTR_PERMISSIONS ? attrs.permissions : DEFAULT_FILE_PERM;

    /* Open file */
    fd = open(sz_filename, flags, mode);
    if (fd < 0)
    {
        status = errno_to_sftp(errno);
    }
    else
    {
        unsigned long handle = handle_alloc_file(fd);
        if (handle == 0)
        {
            /* Out of handles */
            close(fd);
        }
        else
        {
            /* We have opened the file and successfully given it a handle */
            put_handle(id, handle);
            return;
        }
    }
    put_status(id, status);
}

static void sftp_close(void)
{
    uint32_t id;
    uint32_t status = SSH_FX_OK;
    fxp_handle_t *p_handle;

    id = get_uint32();
    p_handle = get_handle();

    if (!p_handle)
    {
        status = SSH_FX_FAILURE;
    }
    else
    {
        if (p_handle->use == HANDLE_FILE)
        {
            if (-1 == close(p_handle->fd))
            {
                status = errno_to_sftp(errno);
            }
        }
        else if (p_handle->use == HANDLE_DIR)
        {
            /* closedir() also closes the underlying  file  descriptor  associated  with  p_dir */
            if (-1 == closedir(p_handle->p_dir))
            {
                status = errno_to_sftp(errno);
            }
        }
        /* Free handle. p_handle->use invalid is successfully freed but should never occur */
        p_handle->use = HANDLE_FREE;
    }
    put_status(id, status);
}

static void sftp_read(void)
{
    /* DATA packet begins opcode, id, length-of-data */
    const uint32_t hdr_size = 1 + 4 + 4;
    uint32_t id, len, max_len;
    fxp_handle_t *p_handle;
    uint64_t offset;
    int status = SSH_FX_FAILURE;

    /* Read request */
    id = get_uint32();
    p_handle = get_handle();
    offset = get_uint64();
    len = get_uint32();

    /* Maximum read length must fit in buffer after header.
    !!! TODO - Different SFTP drafts say different things about shortening reads */
    max_len = obuff.count - hdr_size;
    if (len > max_len)
    {
        len = max_len;
    }
    if (p_handle && p_handle->use == HANDLE_FILE)
    {
        if (lseek(p_handle->fd, offset, SEEK_SET) < 0)
        {
            status = errno_to_sftp(errno);
        }
        else
        {
            /* Read the data directly into the output buffer */
            int ret = read(p_handle->fd, &obuff.p_data[hdr_size], len);

            if (ret < 0)
            {
                status = errno_to_sftp(errno);
            }
            else if (ret == 0)
            {
                status = SSH_FX_EOF;
            }
            else
            {
                /* Successful read some data (may be less than we requested) */
                assert((unsigned)ret <= len);
                put_byte(SSH_FXP_DATA);
                put_uint32(id);
                put_uint32(ret);
                obuff.count -= ret;
                obuff.p_data += ret;
                return;
            }
        }
    }
    put_status(id, status);
}

static void sftp_write(void)
{
    uint32_t id;
    fxp_handle_t *p_handle;
    uint64_t offset;
    const uint8_t *p_data;
    uint32_t data_len;
    int status = SSH_FX_FAILURE;

    /* Parse packet */
    id = get_uint32();
    p_handle = get_handle();
    offset = get_uint64();
    p_data = get_data(&data_len);

    if (p_handle && p_handle->use == HANDLE_FILE)
    {
        if (lseek(p_handle->fd, offset, SEEK_SET) < 0)
        {
            status = errno_to_sftp(errno);
        }
        else
        {
            int ret = write(p_handle->fd, p_data, data_len);

            if (ret < 0)
            {
                status = errno_to_sftp(errno);
            }
            else if ((unsigned)ret == data_len)
            {
                status = SSH_FX_OK;
            }
        }
    }
    put_status(id, status);
}

static void stat_to_attr(struct stat *p_stat, attrs_t *p_attr)
{
    memset(p_attr, 0, sizeof(*p_attr));
    p_attr->flags = SSH_FILEXFER_ATTR_SIZE
        | SSH_FILEXFER_ATTR_UIDGID
        | SSH_FILEXFER_ATTR_PERMISSIONS
        | SSH_FILEXFER_ATTR_ACMODTIME;
    p_attr->size = p_stat->st_size;
    p_attr->uid = p_stat->st_uid;
    p_attr->gid = p_stat->st_gid;
    p_attr->permissions = p_stat->st_mode;
    p_attr->atime = p_stat->st_atime;
    p_attr->mtime = p_stat->st_mtime;
}

static void do_stat(ssh_bool_t follow_symlinks)
{
    uint32_t id = get_uint32();
    const char *sz_path = get_string(NULL);
    struct stat st;
    int ret = follow_symlinks ? stat(sz_path, &st) : lstat(sz_path, &st);

    if (ret < 0)
    {
        put_status(id, errno_to_sftp(errno));
    }
    else
    {
        attrs_t attr;
        stat_to_attr(&st, &attr);
        put_byte(SSH_FXP_ATTRS);
        put_uint32(id);
        put_attrs(&attr);
    }
}

static void sftp_stat(void)
{
    do_stat(SSH_TRUE);
}

static void sftp_lstat(void)
{
    do_stat(SSH_FALSE);
}

static void sftp_fstat(void)
{
    uint32_t id = get_uint32();
    fxp_handle_t *p_handle = get_handle();
    uint32_t status = SSH_FX_FAILURE;

    if (p_handle && p_handle->use == HANDLE_FILE)
    {
        struct stat st;
        if (fstat(p_handle->fd, &st) == 0)
        {
            attrs_t attr;
            stat_to_attr(&st, &attr);
            put_byte(SSH_FXP_ATTRS);
            put_uint32(id);
            put_attrs(&attr);
            return;
        }
        else
        {
            status = errno_to_sftp(errno);
        }
    }
    put_status(id, status);
}

static void sftp_setstat(void)
{
    uint32_t id = get_uint32();
    const char *sz_path = get_string(NULL);
    attrs_t attr;

    get_attrs(&attr);
    if (attr.flags & SSH_FILEXFER_ATTR_PERMISSIONS)
    {
        if (chmod(sz_path, attr.permissions & PERM_MASK) < 0)
        {
            put_status(id, errno_to_sftp(errno));
            return;
        }
    }
    if (attr.flags & SSH_FILEXFER_ATTR_ACMODTIME)
    {
        struct timeval tv[2];

        attrs_to_tv(&attr, tv);
        if (utimes(sz_path, tv) < 0)
        {
            put_status(id, errno_to_sftp(errno));
            return;
        }
    }
    if (attr.flags & SSH_FILEXFER_ATTR_UIDGID)
    {
        if (chown(sz_path, attr.uid, attr.gid) < 0)
        {
            put_status(id, errno_to_sftp(errno));
            return;
        }
    }
    put_status(id, SSH_FX_OK);
}

static void sftp_fsetstat(void)
{
#ifdef _BSD_SOURCE
    uint32_t id = get_uint32();
    fxp_handle_t *p_handle = get_handle();
    uint32_t status = SSH_FX_FAILURE;
    attrs_t attr;

    get_attrs(&attr);
    if (p_handle && p_handle->use == HANDLE_FILE)
    {
        if (attr.flags & SSH_FILEXFER_ATTR_PERMISSIONS)
        {
            if (fchmod(p_handle->fd, attr.permissions & 0777) < 0)
            {
                put_status(id, errno_to_sftp(errno));
                return;
            }
        }
        if (attr.flags & SSH_FILEXFER_ATTR_ACMODTIME)
        {
            struct timeval tv[2];
            attrs_to_tv(&attr, tv);
            if (futimes(p_handle->fd, tv) < 0)
            {
                put_status(id, errno_to_sftp(errno));
                return;
            }
        }
        if (attr.flags & SSH_FILEXFER_ATTR_UIDGID)
        {
            if (fchown(p_handle->fd, attr.uid, attr.gid) < 0)
            {
                put_status(id, errno_to_sftp(errno));
                return;
            }
        }
        status = SSH_FX_OK;
    }
    put_status(id, status);
#else
    put_status(get_uint32(), SSH_FX_OP_UNSUPPORTED);    
#endif
}

static void sftp_opendir(void)
{
    int fd;
    DIR *p_dir;
    uint32_t id = get_uint32();
    const char *sz_path = get_string(NULL);
    int status = SSH_FX_FAILURE;

    /* Open the directory and obtain both a DIR* and a file descriptor.
    Later, when we come to read the directory this allows us to stat
    files in the directory without having to store or catenate the path
    to the files */
    fd = open(sz_path, O_RDONLY);
    if (fd == -1)
    {
        status = errno_to_sftp(errno);
    }
    else
    {
        p_dir = fdopendir(fd);
        if (!p_dir)
        {
            status = errno_to_sftp(errno);
        }
        else
        {
            unsigned long handle = handle_alloc_dir(fd, p_dir);
            if (handle != 0)
            {
                put_handle(id, handle);
                return;
            }
        }
    }
    put_status(id, status);
}

static void sftp_readdir(void)
{
    buff_save_t save1,save2;
    uint32_t count = 0;
    struct dirent *p_entry;
    uint32_t id = get_uint32();
    fxp_handle_t *p_handle = get_handle();

    if (!p_handle)
    {
        put_status(id, SSH_FX_FAILURE);
        return;
    }
    /* Proceed to write a NAME packet; but save the buffer pointers in case we give
    up and write a STATUS instead. Save the position of count so that we can update
    it at the end */
    buff_save(&save1);
    put_byte(SSH_FXP_NAME);
    put_uint32(id);
    buff_save(&save2);
    put_uint32(count);

    do
    {
        attrs_t attr;
        struct stat st;
        long dir_posn = telldir(p_handle->p_dir);

        p_entry = readdir(p_handle->p_dir);
        if (p_entry)
        {
            /* Ignore entries we can't stat */
            if (fstatat(p_handle->fd, p_entry->d_name, &st, 0) < 0)
            {
                continue;
            }
            /* If the entry will fit in the buffer */
            if (((strlen(p_entry->d_name) + sizeof(uint32_t)) * 2 + MAX_ATTRS_BYTES) <= obuff.count)
            {
                put_cstring(p_entry->d_name);
                put_cstring(p_entry->d_name);
                stat_to_attr(&st, &attr);
                put_attrs(&attr);
                count++;
            }
            else if (count > 0)
            {
                /* We couldn't write the name to the buffer and it's not the only 
                name in the buffer - rewind the dir pointer and leave it to next time */
                seekdir(p_handle->p_dir, dir_posn);
            }
            /* else - we skip entries too long to ever report! This seems more helpful than
            returning an error and refusing to read anything. */
        }
    } while (p_entry);

    if (count > 0)
    {
        buff_swap(&save2);
        put_uint32(count);
        buff_swap(&save2);
    }
    else
    {
        buff_swap(&save1);
        put_status(id, SSH_FX_EOF);
    }
}

static void sftp_remove(void)
{
    uint32_t id = get_uint32();
    const char *sz_filename = get_string(NULL);

    if (-1 == remove(sz_filename))
    {
        put_status(id, errno_to_sftp(errno));
    }
    else
    {
        put_status(id, SSH_FX_OK);
    }
}

static void sftp_mkdir(void)
{
    uint32_t id = get_uint32();
    const char *sz_path = get_string(NULL);
    attrs_t attr;
    mode_t mode;

    get_attrs(&attr);
    if (attr.flags & SSH_FILEXFER_ATTR_PERMISSIONS)
    {
        mode = attr.permissions & PERM_MASK;
    }
    else
    {
        mode = DEFAULT_DIR_PERM;
    }
    /* Ignore other attrs */
    if (-1 == mkdir(sz_path, mode))
    {
        put_status(id, errno_to_sftp(errno));
    }
    else
    {
        put_status(id, SSH_FX_OK);
    }
}

static void sftp_rmdir(void)
{
    uint32_t id = get_uint32();
    const char *sz_path = get_string(NULL);

    if (-1 == rmdir(sz_path))
    {
        put_status(id, errno_to_sftp(errno));
    }
    else
    {
        put_status(id, SSH_FX_OK);
    }
}

static void sftp_realpath(void)
{
#if defined(_POSIX_C_SOURCE) && _POSIX_C_SOURCE >= 200809L
    uint32_t id = get_uint32();
    const char *sz_path = get_string(NULL);
    char *sz_fullname;
    attrs_t attr;

    sz_fullname = realpath(sz_path, NULL);
    if (!sz_fullname)
    {
        put_status(id, errno_to_sftp(errno));
        return;
    }

    put_byte(SSH_FXP_NAME);
    put_uint32(id);
    put_uint32(1);  /* 1 name */
    put_cstring(sz_fullname);
    put_cstring(sz_fullname);
    free(sz_fullname);  /* Storage is malloc'd by C library or OS */
    memset(&attr, 0, sizeof(attr));
    put_attrs(&attr);/* dummy attributes - why does SFTP specify this? Why not real attributes?*/
#else
    put_status(get_uint32(), SSH_FX_OP_UNSUPPORTED);    
#endif
}

static void sftp_rename(void)
{
    uint32_t id = get_uint32();
    const char *sz_old_path = get_string(NULL);
    const char *sz_new_path = get_string(NULL);

    if (rename(sz_old_path, sz_new_path) == -1)
    {
        put_status(id, errno_to_sftp(errno));
    }
    else
    {
        put_status(id, SSH_FX_OK);
    }
}

static void sftp_readlink(void)
{
    uint32_t id = get_uint32();
    const char *sz_path = get_string(NULL);
    buff_save_t save;
    attrs_t attr;
    char *p_target;
    uint32_t space;
    int len;

    /* Save the buffer position in case we come back and write status instead */
    buff_save(&save);

    /* Proceed as if readlink will succeed, read directly into the output buffer. */
    put_byte(SSH_FXP_NAME);
    put_uint32(id);
    put_uint32(1);  /* 1 name */
    
    /* After attrs, space is two names - two SSH strings with 4-byte length fields. */
    space = (obuff.count - MAX_ATTRS_BYTES)/2 - sizeof(uint32_t);
    p_target = (char *)obuff.p_data + sizeof(uint32_t);
    len = readlink(sz_path, p_target, space);
    if (len == -1)
    {
        buff_swap(&save);
        put_status(id, errno_to_sftp(errno));
    }
    else
    {
        put_uint32(len);
        obuff.count -= len;
        obuff.p_data += len;
        p_target[len] = '\0'; 
        put_cstring(p_target);
        memset(&attr, 0, sizeof(attr));
        put_attrs(&attr);/* dummy attributes - why does SFTP specify this? Why not real attributes?*/
    }
}

static void sftp_symlink(void)
{
    uint32_t id = get_uint32();
    const char *sz_link_path = get_string(NULL);
    const char *sz_target_path = get_string(NULL);

    if (symlink(sz_target_path, sz_link_path) == -1) /* !!! TODO Other implementations have these the other way around */
    {
        put_status(id, errno_to_sftp(errno));
    }
    else
    {
        put_status(id, SSH_FX_OK);
    }
}

static void put_status(uint32_t id, uint32_t status)
{
    put_byte(SSH_FXP_STATUS);
    put_uint32(id);
    put_uint32(status);

    switch (status)
    {
    case SSH_FX_OK:
        put_cstring("Success");
        break;

    case SSH_FX_EOF:
        put_cstring("End of file");
        break;

    case SSH_FX_NO_SUCH_FILE:
        put_cstring("No such file");
        break;

    case SSH_FX_PERMISSION_DENIED:
        put_cstring("Permission denied");
        break;

    case SSH_FX_FAILURE:
        put_cstring("Failure");
        break;

    case SSH_FX_BAD_MESSAGE:
        put_cstring("Bad message");
        break;

    /* case SSH_FX_NO_CONNECTION, SSH_FX_CONNECTION_LOST MUST NOT be returned by servers */

    case SSH_FX_OP_UNSUPPORTED:
        put_cstring("Operation unsupported");
        break;

    default:
        put_cstring("Unknown error");
        break;
    }
    /* Language tag */
    put_cstring("en");
}

static void put_handle(uint32_t id, unsigned long handle)
{
    char buff[MAX_HANDLE_DIGITS + 1];
    assert(handle > 0);
    assert(handle <= elemof(handles));

    put_byte(SSH_FXP_HANDLE);
    put_uint32(id);
    sprintf(buff,"%0" STREXPAND(MAX_HANDLE_DIGITS) "lu", handle);
    put_cstring(buff);
}

/* Obtains a handle string from the input buffer and returns either a
pointer to a handle if the handle was valid, or NULL otherwise */
static fxp_handle_t *get_handle(void)
{
    const char *sz_handle;
    uint32_t handle_len;
    unsigned long handle;
    char *ep;

    sz_handle = get_string(&handle_len);

    if (handle_len != MAX_HANDLE_DIGITS)
    {
        return NULL;
    }
    handle = strtoul(sz_handle, &ep, 10);
    if (*ep != '\0')
    {
        /* Didn't convert all characters */
        return NULL;
    }
    if (handle == 0)
    {
        /* Didn't convert string (or was zero which isn't a valid handle) */
        return NULL;
    }
    if (handle > elemof(handles))
    {
        /* Out of range */
        return NULL;
    }
    if (handles[handle - 1].use == HANDLE_FREE)
    {
        /* Not allocated */
        return NULL;
    }
    return &handles[handle - 1];
}

static void buff_save(buff_save_t *p_buff)
{
    p_buff->count = obuff.count;
    p_buff->p_data = obuff.p_data;
}

static void buff_swap(buff_save_t *p_buff)
{
    uint32_t temp = obuff.count;
    uint8_t *p_temp = obuff.p_data;

    obuff.count = p_buff->count;
    obuff.p_data = p_buff->p_data;
    p_buff->count = temp;
    p_buff->p_data = p_temp;
}

/* RFC4251 byte
      A byte represents an arbitrary 8-bit value (octet).  Fixed length
      data is sometimes represented as an array of bytes, written
      byte[n], where n is the number of bytes in the array.*/
static uint8_t get_byte(void)
{
    uint8_t data;

    /* Check we're safe */
    assert(ibuff.count > 0);
    data = *ibuff.p_data;

    /* Adjust pointers */
    ibuff.count--;
    ibuff.p_data++;

    return data;
}

static void put_byte(uint8_t data)
{
    assert(obuff.count > 0);

    *obuff.p_data = data;

    /* Adjust pointers */
    obuff.count--;
    obuff.p_data++;
}

/* RFC4251
      A boolean value is stored as a single byte.  The value 0
      represents FALSE, and the value 1 represents TRUE.  All non-zero
      values MUST be interpreted as TRUE; however, applications MUST NOT
      store values other than 0 and 1. */
/* Not needed static ssh_bool_t get_bool(void)
{
    uint8_t data = get_byte();
    return data == 0 ? SSH_FALSE : SSH_TRUE;
} */

/* RFC4251 uint32
Represents a 32-bit unsigned integer.  Stored as four bytes in the
      order of decreasing significance (network byte order).  For
      example: the value 699921578 (0x29b7f4aa) is stored as 29 b7 f4
      aa.*/
static uint32_t get_uint32(void)
{
    uint32_t data;

    /* Check we're safe */
    assert(ibuff.count >= 4);

    /* Obtain uint32_t in network byte order (big-endian) */
    data = (((uint32_t)ibuff.p_data[0]) << 24) |
           (((uint32_t)ibuff.p_data[1]) << 16) |
           (((uint32_t)ibuff.p_data[2]) <<  8) |
           (((uint32_t)ibuff.p_data[3])      );

    /* Update buffer deteails */
    ibuff.count -= 4;
    ibuff.p_data += 4;

    return data;
}

static uint64_t get_uint64(void)
{
    uint64_t data;

    data = get_uint32();
    data = (data << 32) | get_uint32();
    return data;
}

static void put_uint32(uint32_t data)
{
    /* Check for space */
    assert(obuff.count >= 4);

    /* Write in network byte order (big-endian) */
    obuff.p_data[0] = (uint8_t)(data >> 24);
    obuff.p_data[1] = (uint8_t)(data >> 16);
    obuff.p_data[2] = (uint8_t)(data >>  8);
    obuff.p_data[3] = (uint8_t)(data      );

    /* Accounting */
    obuff.count -= 4;
    obuff.p_data += 4;
}

static void put_uint64(uint64_t data)
{
    put_uint32((uint32_t)(data >> 32));
    put_uint32((uint32_t)data);
}

/* RC4251 string
      Arbitrary length binary string.  Strings are allowed to contain
      arbitrary binary data, including null characters and 8-bit
      characters.  They are stored as a uint32 containing its length
      (number of bytes that follow) and zero (= empty string) or more
      bytes that are the value of the string.  Terminating null
      characters are not used.

      Strings are also used to store text.  In that case, US-ASCII is
      used for internal names, and ISO-10646 UTF-8 for text that might
      be displayed to the user.  The terminating null character SHOULD
      NOT normally be stored in the string.  For example: the US-ASCII
      string "testing" is represented as 00 00 00 07 t e s t i n g.  The
      UTF-8 mapping does not alter the encoding of US-ASCII characters.

      Strings returned here are only valid until the next input packet
      is received; they must be copied if they are needed for longer
      than this.
*/
static const char *get_string(uint32_t *p_sz_len)
{
    uint32_t len_bytes;
    uint8_t *p_sz;

    /* Obtain a pointer to where the length field currently is */
    p_sz = ibuff.p_data;

    /* Obtain length of string and check it is inside the packet*/
    len_bytes = get_uint32();
    assert(len_bytes <= ibuff.count);

    /* Move the string earlier in memory by 4 bytes and append null terminator */
    memmove(p_sz, ibuff.p_data, len_bytes);
    p_sz[len_bytes] = '\0';

    /* Consume the length of the string */
    ibuff.count -= len_bytes;
    ibuff.p_data += len_bytes;

    /* Return the length if required */
    if (p_sz_len)
    {
        *p_sz_len = len_bytes;
    }
    /* The cast to const adds a small amount of safety... once
    we've messed with a string in this manner it shouldn't be used
    where it might be modified */
    return (const char*)p_sz;
}

/* Return data string (i.e. not null terminated, may contain arbitrary bytes
including zeros). Only valid while the input packet hangs around */
static const uint8_t *get_data(uint32_t *p_len)
{
    const uint8_t *p_data;
    uint32_t len_bytes = get_uint32();
    assert(len_bytes <= ibuff.count);

    p_data = ibuff.p_data;
    if (p_len)
    {
        *p_len = len_bytes;
    }

    ibuff.count -= len_bytes;
    ibuff.p_data += len_bytes;

    return p_data;
}

/* Write a C string. We trust this to be a properly null terminated string
i.e. originates in our code or an OS call, not from the client */
static void put_cstring(const char *sz_str)
{
    size_t len = strlen(sz_str);

    put_uint32(len);
    assert(len  <= obuff.count);
    memcpy(obuff.p_data, sz_str, len);

    obuff.count -= len;
    obuff.p_data += len;
}

/* Get ATTRs */
static void get_attrs(attrs_t *p_attrs)
{
    memset(p_attrs, 0, sizeof(*p_attrs));

    p_attrs->flags = get_uint32();
    if (p_attrs->flags & SSH_FILEXFER_ATTR_SIZE)
    {
        p_attrs->size = get_uint64();
    }
    if (p_attrs->flags & SSH_FILEXFER_ATTR_UIDGID)
    {
        p_attrs->uid = get_uint32();
        p_attrs->gid = get_uint32();
    }
    if (p_attrs->flags & SSH_FILEXFER_ATTR_PERMISSIONS)
    {
        p_attrs->permissions = get_uint32();
    }
    if (p_attrs->flags & SSH_FILEXFER_ATTR_ACMODTIME)
    {
        p_attrs->atime = get_uint32();
        p_attrs->mtime = get_uint32();
    }
    if (p_attrs->flags & SSH_FILEXFER_ATTR_EXTENDED)
    {
        /* Note: ATTRs appears to be always at the end of the input packet so it
        is probably safe to ignore extensions. Consuming the infromation we don't
        want is however safer */
        uint32_t count = get_uint32();

        while(count--)
        {
            /* Discard extended_type, extended_data pairs */
            get_string(NULL);
            get_string(NULL);
        }
    }

}

static void put_attrs(attrs_t *p_attrs)
{
    put_uint32(p_attrs->flags);
    if (p_attrs->flags & SSH_FILEXFER_ATTR_SIZE)
    {
        put_uint64(p_attrs->size);
    }
    if (p_attrs->flags & SSH_FILEXFER_ATTR_UIDGID)
    {
        put_uint32(p_attrs->uid);
        put_uint32(p_attrs->gid);
    }
    if (p_attrs->flags & SSH_FILEXFER_ATTR_PERMISSIONS)
    {
        put_uint32(p_attrs->permissions);
    }
    if (p_attrs->flags & SSH_FILEXFER_ATTR_ACMODTIME)
    {
        put_uint32(p_attrs->atime);
        put_uint32(p_attrs->mtime);
    }
}

static void attrs_to_tv(attrs_t *p_attr, struct timeval tv[2])
{
    tv[0].tv_sec = p_attr->atime;
    tv[0].tv_usec = 0;
    tv[1].tv_sec = p_attr->mtime;
    tv[1].tv_usec = 0;
}

/* Map portable flags to unix flags */
static int pflags_to_unix(uint32_t pflags)
{
    int flags = 0;
    if ((pflags & SSH_FXF_READ) && (pflags & SSH_FXF_WRITE))
    {
        flags = O_RDWR;
    }
    else if (pflags & SSH_FXF_READ)
    {
        flags = O_RDONLY;
    }
    else if (pflags & SSH_FXF_WRITE)
    {
        flags = O_WRONLY;
    }
    if (pflags & SSH_FXF_CREAT)
    {
        flags |= O_CREAT;
    }
    if (pflags & SSH_FXF_TRUNC)
    {
        flags |= O_TRUNC;
    }
    if (pflags & SSH_FXF_EXCL)
    {
        flags |= O_EXCL;
    }
    return flags;
}

/* Map errno() to SFTP error code */
static uint32_t errno_to_sftp(int unix_error)
{
    switch (unix_error)
    {
    case 0:
        return SSH_FX_OK;

    case ENOENT:
    case ENOTDIR:
    case EBADF:
    case ELOOP:
        return SSH_FX_NO_SUCH_FILE;

    case EPERM:
    case EACCES:
    case EFAULT:
        return SSH_FX_PERMISSION_DENIED;

    case ENAMETOOLONG:
    case EINVAL:
        return SSH_FX_BAD_MESSAGE;
    }
    return SSH_FX_FAILURE;
}

/* Return handle number 1..elemof(handles), or 0 on error. Note that stroul and friends
can return 0 on error so it's best avoided as a handle number */
static unsigned long handle_alloc_file(int fd)
{
    unsigned long handle;
    for (handle = 0; handle < elemof(handles); handle++)
    {
        if (handles[handle].use == HANDLE_FREE)
        {
            handles[handle].use = HANDLE_FILE;
            handles[handle].fd = fd;
            return handle + 1;
        }
    }
    fprintf(stderr,"Out of handles\n");
    return 0;
}

static unsigned long handle_alloc_dir(int fd, DIR *p_dir)
{
    unsigned long handle;
    for (handle = 0; handle < elemof(handles); handle++)
    {
        if (handles[handle].use == HANDLE_FREE)
        {
            handles[handle].use = HANDLE_DIR;
            handles[handle].fd = fd;
            handles[handle].p_dir = p_dir;
            return handle + 1;
        }
    }
    fprintf(stderr,"Out of handles\n");
    return 0;
}
/* End of file */

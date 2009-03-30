 /*
  * UAE - The Un*x Amiga Emulator
  *
  * routines to handle compressed file automatically
  *
  * (c) 1996 Samuel Devulder
  */

struct zfile;
struct zvolume;

typedef int (*zfile_callback)(struct zfile*, void*);

extern struct zfile *zfile_fopen (const TCHAR *, const TCHAR *);
extern struct zfile *zfile_fopen_nozip (const TCHAR *, const TCHAR *);
extern struct zfile *zfile_fopen_empty (const TCHAR *name, uae_u64 size);
extern struct zfile *zfile_fopen_data (const TCHAR *name, uae_u64 size, uae_u8 *data);
extern int zfile_exists (const TCHAR *name);
extern void zfile_fclose (struct zfile *);
extern uae_s64 zfile_fseek (struct zfile *z, uae_s64 offset, int mode);
extern uae_s64 zfile_ftell (struct zfile *z);
extern size_t zfile_fread  (void *b, size_t l1, size_t l2, struct zfile *z);
extern size_t zfile_fwrite  (void *b, size_t l1, size_t l2, struct zfile *z);
extern TCHAR *zfile_fgets (TCHAR *s, int size, struct zfile *z);
extern char *zfile_fgetsa (char *s, int size, struct zfile *z);
extern size_t zfile_fputs (struct zfile *z, TCHAR *s);
extern int zfile_getc (struct zfile *z);
extern int zfile_putc (int c, struct zfile *z);
extern int zfile_ferror (struct zfile *z);
extern uae_u8 *zfile_getdata (struct zfile *z, uae_s64 offset, int len);
extern void zfile_exit (void);
extern int execute_command (TCHAR *);
extern int zfile_iscompressed (struct zfile *z);
extern int zfile_zcompress (struct zfile *dst, void *src, int size);
extern int zfile_zuncompress (void *dst, int dstsize, struct zfile *src, int srcsize);
extern int zfile_gettype (struct zfile *z);
extern int zfile_zopen (const TCHAR *name, zfile_callback zc, void *user);
extern TCHAR *zfile_getname (struct zfile *f);
extern uae_u32 zfile_crc32 (struct zfile *f);
extern struct zfile *zfile_dup (struct zfile *f);
extern struct zfile *zfile_gunzip (struct zfile *z);
extern int zfile_isdiskimage (const TCHAR *name);
extern int iszip (struct zfile *z);
extern int zfile_convertimage (const TCHAR *src, const TCHAR *dst);

#define ZFILE_UNKNOWN 0
#define ZFILE_CONFIGURATION 1
#define ZFILE_DISKIMAGE 2
#define ZFILE_ROM 3
#define ZFILE_KEY 4
#define ZFILE_HDF 5
#define ZFILE_STATEFILE 6
#define ZFILE_NVR 7
#define ZFILE_HDFRDB 8

extern const TCHAR *uae_archive_extensions[];
extern const TCHAR *uae_ignoreextensions[];
extern const TCHAR *uae_diskimageextensions[];

extern struct zvolume *zfile_fopen_archive(const TCHAR *filename);
extern void zfile_fclose_archive(struct zvolume *zv);
extern int zfile_fs_usage_archive(const TCHAR *path, const TCHAR *disk, struct fs_usage *fsp);
extern int zfile_stat_archive(const TCHAR *path, struct _stat64 *statbuf);
extern void *zfile_opendir_archive(const TCHAR *path);
extern void zfile_closedir_archive(void*);
extern int zfile_readdir_archive(void*, TCHAR*);
extern zfile_fill_file_attrs_archive(const TCHAR *path, int *isdir, int *flags, TCHAR **comment);
extern uae_s64 zfile_lseek_archive (void *d, uae_s64 offset, int whence);
extern unsigned int zfile_read_archive (void *d, void *b, unsigned int size);
extern void zfile_close_archive (void *d);
extern void *zfile_open_archive (const TCHAR *path, int flags);
extern int zfile_exists_archive(const TCHAR *path, const TCHAR *rel);

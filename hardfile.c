 /*
  * UAE - The Un*x Amiga Emulator
  *
  * Hardfile emulation
  *
  * Copyright 1995 Bernd Schmidt
  *           2002 Toni Wilen (scsi emulation, 64-bit support)
  */

#include "sysconfig.h"
#include "sysdeps.h"

#include "threaddep/thread.h"
#include "options.h"
#include "memory.h"
#include "custom.h"
#include "newcpu.h"
#include "disk.h"
#include "autoconf.h"
#include "traps.h"
#include "filesys.h"
#include "execlib.h"
#include "native2amiga.h"
#include "gui.h"
#include "uae.h"
#include "scsi.h"

#define CMD_INVALID	0
#define CMD_RESET	1
#define CMD_READ	2
#define CMD_WRITE	3
#define CMD_UPDATE	4
#define CMD_CLEAR	5
#define CMD_STOP	6
#define CMD_START	7
#define CMD_FLUSH	8
#define CMD_MOTOR	9
#define CMD_SEEK	10
#define CMD_FORMAT	11
#define CMD_REMOVE	12
#define CMD_CHANGENUM	13
#define CMD_CHANGESTATE	14
#define CMD_PROTSTATUS	15
#define CMD_GETDRIVETYPE 18
#define CMD_GETNUMTRACKS 19
#define CMD_ADDCHANGEINT 20
#define CMD_REMCHANGEINT 21
#define CMD_GETGEOMETRY	22
#define HD_SCSICMD 28

/* Trackdisk64 support */
#define TD_READ64 24
#define TD_WRITE64 25
#define TD_SEEK64 26
#define TD_FORMAT64 27

/* New Style Devices (NSD) support */
#define DRIVE_NEWSTYLE 0x4E535459L   /* 'NSTY' */
#define NSCMD_DEVICEQUERY 0x4000
#define NSCMD_TD_READ64 0xc000
#define NSCMD_TD_WRITE64 0xc001
#define NSCMD_TD_SEEK64 0xc002
#define NSCMD_TD_FORMAT64 0xc003

#undef DEBUGME
#define hf_log
#define hf_log2
#define scsi_log
#define hf_log3

//#define DEBUGME
#ifdef DEBUGME
#undef hf_log
#define hf_log write_log
#undef hf_log2
#define hf_log2 write_log
#undef scsi_log
#define scsi_log write_log
#endif

#define MAX_ASYNC_REQUESTS 50
#define ASYNC_REQUEST_NONE 0
#define ASYNC_REQUEST_TEMP 1
#define ASYNC_REQUEST_CHANGEINT 10

struct hardfileprivdata {
    volatile uaecptr d_request[MAX_ASYNC_REQUESTS];
    volatile int d_request_type[MAX_ASYNC_REQUESTS];
    volatile uae_u32 d_request_data[MAX_ASYNC_REQUESTS];
    smp_comm_pipe requests;
    uae_thread_id tid;
    int thread_running;
    uae_sem_t sync_sem;
    uaecptr base;
    int changenum;
};

static uae_sem_t change_sem;

static struct hardfileprivdata hardfpd[MAX_FILESYSTEM_UNITS];

static uae_u32 nscmd_cmd;

static void wl (uae_u8 *p, int v)
{
    p[0] = v >> 24;
    p[1] = v >> 16;
    p[2] = v >> 8;
    p[3] = v;
}
static void ww (uae_u8 *p, int v)
{
    p[0] = v >> 8;
    p[1] = v;
}
static int rl (uae_u8 *p)
{
    return (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | (p[3]);
}


static void getchs2 (struct hardfiledata *hfd, int *cyl, int *cylsec, int *head, int *tracksec)
{
    unsigned int total = (unsigned int)(hfd->size / 1024);
    int heads;
    int sectors = 63;

    /* do we have RDB values? */
    if (hfd->cylinders) {
	*cyl = hfd->cylinders;
	*tracksec = hfd->sectors;
	*head = hfd->heads;
	*cylsec = hfd->sectors * hfd->heads;
	return;
    }
    /* what about HDF settings? */
    if (hfd->surfaces && hfd->secspertrack) {
	*head = hfd->surfaces;
	*tracksec = hfd->secspertrack;
	*cylsec = (*head) * (*tracksec);
	*cyl = (unsigned int)(hfd->size / hfd->blocksize) / ((*tracksec) * (*head));
	return;
    }
    /* no, lets guess something.. */
    if (total <= 504 * 1024)
	heads = 16;
    else if (total <= 1008 * 1024)
	heads = 32;
    else if (total <= 2016 * 1024)
	heads = 64;
    else if (total <= 4032 * 1024)
	heads = 128;
    else
	heads = 255;
    *cyl = (unsigned int)(hfd->size / hfd->blocksize) / (sectors * heads);
    *cylsec = sectors * heads;
    *tracksec = sectors;
    *head = heads;
}

static void getchs (struct hardfiledata *hfd, int *cyl, int *cylsec, int *head, int *tracksec)
{
    getchs2 (hfd, cyl, cylsec, head, tracksec);
    hf_log ("CHS: %08.8X-%08.8X %d %d %d %d %d\n",
	(uae_u32)(hfd->size >> 32),(uae_u32)hfd->size,
	*cyl, *cylsec, *head, *tracksec);
}

void getchshd (struct hardfiledata *hfd, int *pcyl, int *phead, int *psectorspertrack)
{
    unsigned int total = (unsigned int)(hfd->size / 512);
    int i, head , cyl, spt;
    int sptt[] = { 63, 127, 255, -1 };

    if (total > 16515072) {
	 /* >8G, CHS=16383/16/63 */
	*pcyl = 16383;
	*phead = 16;
	*psectorspertrack = 63;
	return;
    }

    for (i = 0; sptt[i] >= 0; i++) {
	spt = sptt[i];
	for (head = 4; head <= 16;head++) {
	    cyl = total / (head * spt);
	    if (hfd->size <= 512 * 1024 * 1024) {
		if (cyl <= 1023)
		    break;
	    } else {
		if (cyl < 16383)
		    break;
		if (cyl < 32767 && head >= 5)
		    break;
		if (cyl <= 65535)
		    break;
	    }
	}
	if (head <= 16)
	    break;
    }
    *pcyl = cyl;
    *phead = head;
    *psectorspertrack = spt;
}

static void pl(uae_u8 *p, int off, uae_u32 v)
{
    p += off * 4;
    p[0] = v >> 24;
    p[1] = v >> 16;
    p[2] = v >> 8;
    p[3] = v >> 0;
}

static void rdb_crc(uae_u8 *p)
{
    uae_u32 sum;
    int i, blocksize;

    sum =0;
    blocksize = rl (p + 1 * 4);
    for (i = 0; i < blocksize; i++)
	sum += rl (p + i * 4);
    sum = -sum;
    pl (p, 2, sum);
}

static void create_virtual_rdb(struct hardfiledata *hfd, uae_u32 dostype, int bootpri, char *filesys)
{
    uae_u8 *rdb, *part, *denv;
    int cyl = hfd->heads * hfd->secspertrack;
    int cyls = 262144 / (cyl * 512);
    int size = cyl * cyls * 512;

    rdb = (uae_u8*)xcalloc (size, 1);
    hfd->virtual_rdb = rdb;
    hfd->virtual_size = size;
    part = rdb + 512;
    pl(rdb, 0, 0x5244534b);
    pl(rdb, 1, 64);
    pl(rdb, 2, 0); // chksum
    pl(rdb, 3, 0); // hostid
    pl(rdb, 4, 512); // blockbytes
    pl(rdb, 5, 0); // flags
    pl(rdb, 6, -1); // badblock
    pl(rdb, 7, 1); // part
    pl(rdb, 8, -1); // fs
    pl(rdb, 9, -1); // driveinit
    pl(rdb, 10, -1); // reserved
    pl(rdb, 11, -1); // reserved
    pl(rdb, 12, -1); // reserved
    pl(rdb, 13, -1); // reserved
    pl(rdb, 14, -1); // reserved
    pl(rdb, 15, -1); // reserved
    pl(rdb, 16, hfd->nrcyls);
    pl(rdb, 17, hfd->secspertrack);
    pl(rdb, 18, hfd->heads);
    pl(rdb, 19, 0); // interleave
    pl(rdb, 20, 0); // park
    pl(rdb, 21, -1); // res
    pl(rdb, 22, -1); // res
    pl(rdb, 23, -1); // res
    pl(rdb, 24, 0); // writeprecomp
    pl(rdb, 25, 0); // reducedwrite
    pl(rdb, 26, 0); // steprate
    pl(rdb, 27, -1); // res
    pl(rdb, 28, -1); // res
    pl(rdb, 29, -1); // res
    pl(rdb, 30, -1); // res
    pl(rdb, 31, -1); // res
    pl(rdb, 32, 0); // rdbblockslo
    pl(rdb, 33, cyl * cyls); // rdbblockshi
    pl(rdb, 34, cyls); // locyl
    pl(rdb, 35, hfd->nrcyls + cyls); // hicyl
    pl(rdb, 36, cyl); // cylblocks
    pl(rdb, 37, 0); // autopark
    pl(rdb, 38, 2); // highrdskblock
    pl(rdb, 39, -1); // res
    strcpy (rdb + 40 * 4, hfd->vendor_id);
    strcpy (rdb + 42 * 4, hfd->product_id);
    strcpy (rdb + 46 * 4, "UAE");
    rdb_crc(rdb);

    pl(part, 0, 0x50415254);
    pl(part, 1, 64);
    pl(part, 2, 0);
    pl(part, 3, 0);
    pl(part, 4, -1);
    pl(part, 5, 1); // bootable
    pl(part, 6, -1);
    pl(part, 7, -1);
    pl(part, 8, 0); // devflags
    part[9 * 4] = strlen(hfd->device_name);
    strcpy (part + 9 * 4 + 1, hfd->device_name);

    denv = part + 128;
    pl(denv, 0, 80);
    pl(denv, 1, 512 / 4);
    pl(denv, 2, 0); // secorg
    pl(denv, 3, hfd->heads);
    pl(denv, 4, hfd->blocksize / 512);
    pl(denv, 5, hfd->secspertrack);
    pl(denv, 6, hfd->reservedblocks);
    pl(denv, 7, 0); // prealloc
    pl(denv, 8, 0); // interleave
    pl(denv, 9, cyls); // lowcyl
    pl(denv, 10, hfd->nrcyls + cyls - 1);
    pl(denv, 11, 50);
    pl(denv, 12, 0);
    pl(denv, 13, 0x00ffffff);
    pl(denv, 14, 0x7ffffffe);
    pl(denv, 15, bootpri);
    pl(denv, 16, dostype);
    rdb_crc(part);

    hfd->size += size;
    hfd->size2 += size;

}

void hdf_hd_close(struct hd_hardfiledata *hfd)
{
    if (!hfd)
	return;
    hdf_close(&hfd->hfd);
    xfree(hfd->path);
}

int hdf_hd_open(struct hd_hardfiledata *hfd, char *path, int blocksize, int readonly,
		       char *devname, int sectors, int surfaces, int reserved,
		       int bootpri, char *filesys)
{
    memset(hfd, 0, sizeof (struct hd_hardfiledata));
    hfd->bootpri = bootpri;
    hfd->hfd.blocksize = blocksize;
    if (!hdf_open(&hfd->hfd, path))
	return 0;
    hfd->path = my_strdup(path);
    hfd->hfd.heads = surfaces;
    hfd->hfd.reservedblocks = reserved;
    hfd->hfd.secspertrack = sectors;
    if (devname)
	strcpy (hfd->hfd.device_name, devname);
    getchshd(&hfd->hfd, &hfd->cyls, &hfd->heads, &hfd->secspertrack);
    hfd->cyls_def = hfd->cyls;
    hfd->secspertrack_def = hfd->secspertrack;
    hfd->heads_def = hfd->heads;
    if (hfd->hfd.heads && hfd->hfd.secspertrack) {
	uae_u8 buf[512] = { 0 };
	hdf_read(&hfd->hfd, buf, 0, 512);
	if (buf[0] != 0 && memcmp(buf, "RDSK", 4)) {
	    hfd->hfd.nrcyls = (hfd->hfd.size / blocksize) / (sectors * surfaces);
	    create_virtual_rdb(&hfd->hfd, rl (buf), hfd->bootpri, filesys);
	    while (hfd->hfd.nrcyls * surfaces * sectors > hfd->cyls_def * hfd->secspertrack_def * hfd->heads_def) {
		hfd->cyls_def++;
	    }
	}
    }
    hfd->size = hfd->hfd.size;
    return 1;
}

static uae_u64 cmd_readx (struct hardfiledata *hfd, uae_u8 *dataptr, uae_u64 offset, uae_u64 len)
{
    gui_hd_led (1);
    hf_log3 ("cmd_read: %p %04.4x-%08.8x (%d) %08.8x (%d)\n",
	dataptr, (uae_u32)(offset >> 32), (uae_u32)offset, (uae_u32)(offset / hfd->blocksize), (uae_u32)len, (uae_u32)(len / hfd->blocksize));
    return hdf_read (hfd, dataptr, offset, len);
}
static uae_u64 cmd_read (struct hardfiledata *hfd, uaecptr dataptr, uae_u64 offset, uae_u64 len)
{
    addrbank *bank_data = &get_mem_bank (dataptr);
    if (!bank_data || !bank_data->check (dataptr, len))
	return 0;
    return cmd_readx (hfd, bank_data->xlateaddr (dataptr), offset, len);
}
static uae_u64 cmd_writex (struct hardfiledata *hfd, uae_u8 *dataptr, uae_u64 offset, uae_u64 len)
{
    gui_hd_led (2);
    hf_log3 ("cmd_write: %p %04.4x-%08.8x (%d) %08.8x (%d)\n",
	dataptr, (uae_u32)(offset >> 32), (uae_u32)offset, (uae_u32)(offset / hfd->blocksize), (uae_u32)len, (uae_u32)(len / hfd->blocksize));
    return hdf_write (hfd, dataptr, offset, len);
}

static uae_u64 cmd_write (struct hardfiledata *hfd, uaecptr dataptr, uae_u64 offset, uae_u64 len)
{
    addrbank *bank_data = &get_mem_bank (dataptr);
    if (!bank_data || !bank_data->check (dataptr, len))
	return 0;
    return cmd_writex (hfd, bank_data->xlateaddr (dataptr), offset, len);
}

static int checkbounds(struct hardfiledata *hfd, uae_u64 offset, uae_u64 len)
{
    if (offset >= hfd->size)
	return 0;
    if (offset + len > hfd->size)
	return 0;
    return 1;
}

int scsi_emulate(struct hardfiledata *hfd, struct hd_hardfiledata *hdhfd, uae_u8 *cmdbuf, int scsi_cmd_len,
		uae_u8 *scsi_data, int *data_len, uae_u8 *r, int *reply_len, uae_u8 *s, int *sense_len)
{
    uae_u64 len, offset;
    int lr = 0, ls = 0;
    int scsi_len = -1;
    int status = 0;
    int i;

    *reply_len = *sense_len = 0;
    memset(r, 0, 256);
    memset(s, 0, 256);
    switch (cmdbuf[0])
    {
	case 0x00: /* TEST UNIT READY */
	break;
	case 0x08: /* READ (6) */
	offset = ((cmdbuf[1] & 31) << 16) | (cmdbuf[2] << 8) | cmdbuf[3];
	offset *= hfd->blocksize;
	len = cmdbuf[4];
	if (!len) len = 256;
	len *= hfd->blocksize;
	if (checkbounds(hfd, offset, len))
	    scsi_len = (uae_u32)cmd_readx (hfd, scsi_data, offset, len);
	break;
	case 0x0a: /* WRITE (6) */
	offset = ((cmdbuf[1] & 31) << 16) | (cmdbuf[2] << 8) | cmdbuf[3];
	offset *= hfd->blocksize;
	len = cmdbuf[4];
	if (!len) len = 256;
	len *= hfd->blocksize;
	if (checkbounds(hfd, offset, len))
	    scsi_len = (uae_u32)cmd_writex (hfd, scsi_data, offset, len);
	break;
	case 0x12: /* INQUIRY */
	if ((cmdbuf[1] & 1) || cmdbuf[2] != 0)
	    goto err;
	len = cmdbuf[4];
	if (cmdbuf[1] >> 5)
	    goto err;//r[0] = 0x7f; /* no lun supported */
	r[2] = 2; /* supports SCSI-2 */
	r[3] = 2; /* response data format */
	r[4] = 32; /* additional length */
	r[7] = 0x20; /* 16 bit bus */
	scsi_len = lr = len < 36 ? (uae_u32)len : 36;
	if (hdhfd) {
	    r[2] = hdhfd->ansi_version;
	    r[3] = hdhfd->ansi_version >= 2 ? 2 : 0;
	    r[7] = hdhfd->ansi_version >= 2 ? 0x20 : 0;
	}
	i = 0; /* vendor id */
	while (i < 8 && hfd->vendor_id[i]) {
	    r[8 + i] = hfd->vendor_id[i];
	    i++;
	}
	while (i < 8) {
	    r[8 + i] = 32;
	    i++;
	}
	i = 0; /* product id */
	while (i < 16 && hfd->product_id[i]) {
	    r[16 + i] = hfd->product_id[i];
	    i++;
	}
	while (i < 16) {
	    r[16 + i] = 32;
	    i++;
	}
	i = 0; /* product revision */
	while (i < 4 && hfd->product_rev[i]) {
	    r[32 + i] = hfd->product_rev[i];
	    i++;
	}
	while (i < 4) {
	    r[32 + i] = 32;
	    i++;
	}
	break;
	case 0x1a: /* MODE SENSE(6) */
	{
	    uae_u8 *p;
	    int pc = cmdbuf[2] >> 6;
	    int pcode = cmdbuf[2] & 0x3f;
	    int dbd = cmdbuf[1] & 8;
	    int cyl, cylsec, head, tracksec;
	    if (hdhfd) {
		cyl = hdhfd->cyls;
		head = hdhfd->heads;
		tracksec = hdhfd->secspertrack;
		cylsec = 0;
	    } else {
		getchs (hfd, &cyl, &cylsec, &head, &tracksec);
	    }
	    //write_log ("MODE SENSE PC=%d CODE=%d DBD=%d\n", pc, pcode, dbd);
	    p = r;
	    p[0] = 4 - 1;
	    p[1] = 0;
	    p[2] = 0;
	    p[3] = 0;
	    p += 4;
	    if (!dbd) {
		uae_u32 blocks = (uae_u32)(hfd->size / hfd->blocksize);
		p[-1] = 8;
		wl(p + 0, blocks);
		wl(p + 4, hfd->blocksize);
		p += 8;
	    }
	    if (pcode == 0) {
		p[0] = 0;
		p[1] = 0;
		p[2] = 0x20;
		p[3] = 0;
		r[0] += 4;
	    } else if (pcode == 3) {
		p[0] = 3;
		p[1] = 24;
		p[3] = 1;
		p[10] = tracksec >> 8;
		p[11] = tracksec;
		p[12] = hfd->blocksize >> 8;
		p[13] = hfd->blocksize;
		p[15] = 1; // interleave
		p[20] = 0x80;
		r[0] += p[1];
	    } else if (pcode == 4) {
		p[0] = 4;
		wl(p + 1, cyl);
		p[1] = 24;
		p[5] = head;
		wl(p + 13, cyl);
		ww(p + 20, 5400);
		r[0] += p[1];
	    } else {
		goto err;
	    }
	    r[0] += r[3];
	    scsi_len = lr = r[0] + 1;
	    break;
	}
	break;
	case 0x1d: /* SEND DIAGNOSTICS */
	break;
	case 0x25: /* READ_CAPACITY */
	{
	    int pmi = cmdbuf[8] & 1;
	    uae_u32 lba = (cmdbuf[2] << 24) | (cmdbuf[3] << 16) | (cmdbuf[2] << 8) | cmdbuf[3];
	    uae_u32 blocks = (uae_u32)(hfd->size / hfd->blocksize - 1);
	    int cyl, cylsec, head, tracksec;
	    if (hdhfd) {
		cyl = hdhfd->cyls;
		head = hdhfd->heads;
		tracksec = hdhfd->secspertrack;
		cylsec = 0;
	    } else {
		getchs (hfd, &cyl, &cylsec, &head, &tracksec);
	    }
	    if (pmi) {
		lba += tracksec * head;
		lba /= tracksec * head;
		lba *= tracksec * head;
		if (lba > blocks)
		    lba = blocks;
		blocks = lba;
	    }
	    wl (r, blocks);
	    wl (r + 4, hfd->blocksize);
	    scsi_len = lr = 8;
	}
	break;
	case 0x28: /* READ (10) */
	offset = rl (cmdbuf + 2);
	offset *= hfd->blocksize;
	len = rl (cmdbuf + 7 - 2) & 0xffff;
	len *= hfd->blocksize;
	if (checkbounds(hfd, offset, len))
	    scsi_len = (uae_u32)cmd_readx (hfd, scsi_data, offset, len);
	break;
	case 0x2a: /* WRITE (10) */
	offset = rl (cmdbuf + 2);
	offset *= hfd->blocksize;
	len = rl (cmdbuf + 7 - 2) & 0xffff;
	len *= hfd->blocksize;
	if (checkbounds(hfd, offset, len))
	    scsi_len = (uae_u32)cmd_writex (hfd, scsi_data, offset, len);
	break;
	case 0x35: /* SYNCRONIZE CACHE (10) */
	break;
	case 0xa8: /* READ (12) */
	offset = rl (cmdbuf + 2);
	offset *= hfd->blocksize;
	len = rl (cmdbuf + 6);
	len *= hfd->blocksize;
	if (checkbounds(hfd, offset, len))
	    scsi_len = (uae_u32)cmd_readx (hfd, scsi_data, offset, len);
	break;
	case 0xaa: /* WRITE (12) */
	offset = rl (cmdbuf + 2);
	offset *= hfd->blocksize;
	len = rl (cmdbuf + 6);
	len *= hfd->blocksize;
	if (checkbounds(hfd, offset, len))
	    scsi_len = (uae_u32)cmd_writex (hfd, scsi_data, offset, len);
	break;
	case 0x37: /* READ DEFECT DATA */
	write_log ("UAEHF: READ DEFECT DATA\n");
	status = 2; /* CHECK CONDITION */
	s[0] = 0x70;
	s[2] = 0; /* NO SENSE */
	s[12] = 0x1c; /* DEFECT LIST NOT FOUND */
	ls = 12;
	break;
	default:
err:
	lr = -1;
	write_log ("UAEHF: unsupported scsi command 0x%02.2X\n", cmdbuf[0]);
	status = 2; /* CHECK CONDITION */
	s[0] = 0x70;
	s[2] = 5; /* ILLEGAL REQUEST */
	s[12] = 0x24; /* ILLEGAL FIELD IN CDB */
	ls = 12;
	break;
    }
    *data_len = scsi_len;
    *reply_len = lr;
    *sense_len = ls;
    return status;
}

static int handle_scsi (uaecptr request, struct hardfiledata *hfd)
{
    uae_u32 acmd = get_long (request + 40);
    uaecptr scsi_data = get_long (acmd + 0);
    uae_u32 scsi_len = get_long (acmd + 4);
    uaecptr scsi_cmd = get_long (acmd + 12);
    uae_u16 scsi_cmd_len = get_word (acmd + 16);
    uae_u8 scsi_flags = get_byte (acmd + 20);
    uaecptr scsi_sense = get_long (acmd + 22);
    uae_u16 scsi_sense_len = get_word (acmd + 26);
    uae_u8 cmd = get_byte (scsi_cmd);
    uae_u8 cmdbuf[256];
    int status, ret = 0, reply_len, sense_len;
    uae_u32 i;
    uae_u8 reply[256], sense[256];
    uae_u8 *scsi_data_ptr = NULL;
    addrbank *bank_data = &get_mem_bank (scsi_data);

    if (bank_data  && bank_data->check (scsi_data, scsi_len))
	scsi_data_ptr = bank_data->xlateaddr (scsi_data);
    scsi_sense_len  = (scsi_flags & 4) ? 4 : /* SCSIF_OLDAUTOSENSE */
	(scsi_flags & 2) ? scsi_sense_len : /* SCSIF_AUTOSENSE */
	32;
    status = 0;
    memset (reply, 0, sizeof reply);
    reply_len = 0; sense_len = 0;
    scsi_log ("hdf scsiemu: cmd=%02.2X,%d flags=%02.2X sense=%p,%d data=%p,%d\n",
	cmd, scsi_cmd_len, scsi_flags, scsi_sense, scsi_sense_len, scsi_data, scsi_len);
    for (i = 0; i < scsi_cmd_len; i++) {
	cmdbuf[i] = get_byte (scsi_cmd + i);
	scsi_log ("%02.2X%c", get_byte (scsi_cmd + i), i < scsi_cmd_len - 1 ? '.' : ' ');
    }
    scsi_log ("\n");

    status = scsi_emulate(hfd, NULL, cmdbuf, scsi_cmd_len, scsi_data_ptr, &scsi_len, reply, &reply_len, sense, &sense_len);

    put_word (acmd + 18, status != 0 ? 0 : scsi_cmd_len); /* fake scsi_CmdActual */
    put_byte (acmd + 21, status); /* scsi_Status */
    if (reply_len > 0) {
	scsi_log ("RD:");
	i = 0;
	while (i < reply_len) {
	    if (i < 24)
		scsi_log ("%02.2X%c", reply[i], i < reply_len - 1 ? '.' : ' ');
	    put_byte (scsi_data + i, reply[i]);
	    i++;
	}
	scsi_log ("\n");
    }
    i = 0;
    if (scsi_sense) {
	while (i < sense_len && i < scsi_sense_len) {
	    put_byte (scsi_sense + i, sense[i]);
	    i++;
	}
    }
    while (i < scsi_sense_len && scsi_sense) {
	put_byte (scsi_sense + i, 0);
	i++;
    }
    if (scsi_len < 0) {
	put_long (acmd + 8, 0); /* scsi_Actual */
	ret = 20;
    } else {
	put_long (acmd + 8, scsi_len); /* scsi_Actual */
    }
    return ret;
}

void hardfile_do_disk_change (int fsid, int insert)
{
    int j;

    write_log("uaehf.device:%d %d\n", fsid, insert);
    uae_sem_wait (&change_sem);
    hardfpd[fsid].changenum++;
    j = 0;
    while (j < MAX_ASYNC_REQUESTS) {
	if (hardfpd[fsid].d_request_type[j] == ASYNC_REQUEST_CHANGEINT) {
	    uae_Cause (hardfpd[fsid].d_request_data[j]);
	}
	j++;
    }
    uae_sem_post (&change_sem);
}

static int add_async_request (struct hardfileprivdata *hfpd, uaecptr request, int type, uae_u32 data)
{
    int i;

    i = 0;
    while (i < MAX_ASYNC_REQUESTS) {
	if (hfpd->d_request[i] == request) {
	    hfpd->d_request_type[i] = type;
	    hfpd->d_request_data[i] = data;
	    hf_log ("old async request %p (%d) added\n", request, type);
	    return 0;
	}
	i++;
    }
    i = 0;
    while (i < MAX_ASYNC_REQUESTS) {
	if (hfpd->d_request[i] == 0) {
	    hfpd->d_request[i] = request;
	    hfpd->d_request_type[i] = type;
	    hfpd->d_request_data[i] = data;
	    hf_log ("async request %p (%d) added (total=%d)\n", request, type, i);
	    return 0;
	}
	i++;
    }
    hf_log ("async request overflow %p!\n", request);
    return -1;
}

static int release_async_request (struct hardfileprivdata *hfpd, uaecptr request)
{
    int i = 0;

    while (i < MAX_ASYNC_REQUESTS) {
	if (hfpd->d_request[i] == request) {
	    int type = hfpd->d_request_type[i];
	    hfpd->d_request[i] = 0;
	    hfpd->d_request_data[i] = 0;
	    hfpd->d_request_type[i] = 0;
	    hf_log ("async request %p removed\n", request);
	    return type;
	}
	i++;
    }
    hf_log ("tried to remove non-existing request %p\n", request);
    return -1;
}

static void abort_async (struct hardfileprivdata *hfpd, uaecptr request, int errcode, int type)
{
    int i;
    hf_log ("aborting async request %p\n", request);
    i = 0;
    while (i < MAX_ASYNC_REQUESTS) {
	if (hfpd->d_request[i] == request && hfpd->d_request_type[i] == ASYNC_REQUEST_TEMP) {
	    /* ASYNC_REQUEST_TEMP = request is processing */
	    sleep_millis (1);
	    i = 0;
	    continue;
	}
	i++;
    }
    i = release_async_request (hfpd, request);
    if (i >= 0)
	hf_log ("asyncronous request=%08.8X aborted, error=%d\n", request, errcode);
}

static void *hardfile_thread (void *devs);
static int start_thread (TrapContext *context, int unit)
{
    struct hardfileprivdata *hfpd = &hardfpd[unit];

    if (hfpd->thread_running)
	return 1;
    memset (hfpd, 0, sizeof (struct hardfileprivdata));
    hfpd->base = m68k_areg (&context->regs, 6);
    init_comm_pipe (&hfpd->requests, 100, 1);
    uae_sem_init (&hfpd->sync_sem, 0, 0);
    uae_start_thread ("hardfile", hardfile_thread, hfpd, &hfpd->tid);
    uae_sem_wait (&hfpd->sync_sem);
    return hfpd->thread_running;
}

static int mangleunit (int unit)
{
    if (unit <= 99)
	return unit;
    if (unit == 100)
	return 8;
    if (unit == 110)
	return 9;
    return -1;
}

static uae_u32 REGPARAM2 hardfile_open (TrapContext *context)
{
    uaecptr tmp1 = m68k_areg (&context->regs, 1); /* IOReq */
    int unit = mangleunit (m68k_dreg (&context->regs, 0));
    struct hardfileprivdata *hfpd = &hardfpd[unit];
    int err = -1;

    /* Check unit number */
    if (unit >= 0 && get_hardfile_data (unit) && start_thread (context, unit)) {
	put_word (hfpd->base + 32, get_word (hfpd->base + 32) + 1);
	put_long (tmp1 + 24, unit); /* io_Unit */
	put_byte (tmp1 + 31, 0); /* io_Error */
	put_byte (tmp1 + 8, 7); /* ln_type = NT_REPLYMSG */
	hf_log ("hardfile_open, unit %d (%d), OK\n", unit, m68k_dreg (&context->regs, 0));
	return 0;
    }
    if (unit < 1000 || is_hardfile(unit) == FILESYS_VIRTUAL)
	err = 50; /* HFERR_NoBoard */
    hf_log ("hardfile_open, unit %d (%d), ERR=%d\n", unit, m68k_dreg (&context->regs, 0), err);
    put_long (tmp1 + 20, (uae_u32)err);
    put_byte (tmp1 + 31, (uae_u8)err);
    return (uae_u32)err;
}

static uae_u32 REGPARAM2 hardfile_close (TrapContext *context)
{
    uaecptr request = m68k_areg (&context->regs, 1); /* IOReq */
    int unit = mangleunit (get_long (request + 24));
    struct hardfileprivdata *hfpd = &hardfpd[unit];

    if (!hfpd)
	return 0;
    put_word (hfpd->base + 32, get_word (hfpd->base + 32) - 1);
    if (get_word (hfpd->base + 32) == 0)
	write_comm_pipe_u32 (&hfpd->requests, 0, 1);
    return 0;
}

static uae_u32 REGPARAM2 hardfile_expunge (TrapContext *context)
{
    return 0; /* Simply ignore this one... */
}

static void outofbounds (int cmd, uae_u64 offset, uae_u64 len, uae_u64 max)
{
    write_log ("UAEHF: cmd %d: out of bounds, %08.8X-%08.8X + %08.8X-%08.8X > %08.8X-%08.8X\n", cmd,
	(uae_u32)(offset >> 32),(uae_u32)offset,(uae_u32)(len >> 32),(uae_u32)len,
	(uae_u32)(max >> 32),(uae_u32)max);
}
static void unaligned (int cmd, uae_u64 offset, uae_u64 len, int blocksize)
{
    write_log ("UAEHF: cmd %d: unaligned access, %08.8X-%08.8X, %08.8X-%08.8X, %08.8X\n", cmd,
	(uae_u32)(offset >> 32),(uae_u32)offset,(uae_u32)(len >> 32),(uae_u32)len,
	blocksize);
}

static uae_u32 hardfile_do_io (struct hardfiledata *hfd, struct hardfileprivdata *hfpd, uaecptr request)
{
    uae_u32 dataptr, offset, actual = 0, cmd;
    uae_u64 offset64;
    int unit = get_long (request + 24);
    uae_u32 error = 0, len;
    int async = 0;
    int bmask = hfd->blocksize - 1;

    cmd = get_word (request + 28); /* io_Command */
    dataptr = get_long (request + 40);
    switch (cmd)
    {
	case CMD_READ:
	offset = get_long (request + 44);
	len = get_long (request + 36); /* io_Length */
	if ((offset & bmask) || (len & bmask)) {
	    unaligned (cmd, offset, len, hfd->blocksize);
	    goto bad_command;
	}
	if (len + offset > hfd->size) {
	    outofbounds (cmd, offset, len, hfd->size);
	    goto bad_command;
	}
	actual = (uae_u32)cmd_read (hfd, dataptr, offset, len);
	break;

	case TD_READ64:
	case NSCMD_TD_READ64:
	offset64 = get_long (request + 44) | ((uae_u64)get_long (request + 32) << 32);
	len = get_long (request + 36); /* io_Length */
	if ((offset64 & bmask) || (len & bmask)) {
	    unaligned (cmd, offset64, len, hfd->blocksize);
	    goto bad_command;
	}
	if (len + offset64 > hfd->size) {
	    outofbounds (cmd, offset64, len, hfd->size);
	    goto bad_command;
	}
	actual = (uae_u32)cmd_read (hfd, dataptr, offset64, len);
	break;

	case CMD_WRITE:
	case CMD_FORMAT: /* Format */
	if (hfd->readonly) {
	    error = 28; /* write protect */
	} else {
	    offset = get_long (request + 44);
	    len = get_long (request + 36); /* io_Length */
	    if ((offset & bmask) || (len & bmask)) {
		unaligned (cmd, offset, len, hfd->blocksize);
		goto bad_command;
	    }
	    if (len + offset > hfd->size) {
		outofbounds (cmd, offset, len, hfd->size);
		goto bad_command;
	    }
	    actual = (uae_u32)cmd_write (hfd, dataptr, offset, len);
	}
	break;

	case TD_WRITE64:
	case TD_FORMAT64:
	case NSCMD_TD_WRITE64:
	case NSCMD_TD_FORMAT64:
	if (hfd->readonly) {
	    error = 28; /* write protect */
	} else {
	    offset64 = get_long (request + 44) | ((uae_u64)get_long (request + 32) << 32);
	    len = get_long (request + 36); /* io_Length */
	    if ((offset64 & bmask) || (len & bmask)) {
		unaligned (cmd, offset64, len, hfd->blocksize);
		goto bad_command;
	    }
	    if (len + offset64 > hfd->size) {
		outofbounds (cmd, offset64, len, hfd->size);
		goto bad_command;
	    }
	    put_long (request + 32, (uae_u32)cmd_write (hfd, dataptr, offset64, len));
	}
	break;

	bad_command:
	error = -5; /* IOERR_BADADDRESS */
	break;

	case NSCMD_DEVICEQUERY:
	    put_long (dataptr + 4, 16); /* size */
	    put_word (dataptr + 8, 5); /* NSDEVTYPE_TRACKDISK */
	    put_word (dataptr + 10, 0);
	    put_long (dataptr + 12, nscmd_cmd);
	    actual = 16;
	break;

	case CMD_GETDRIVETYPE:
	    actual = DRIVE_NEWSTYLE;
	    break;

	case CMD_GETNUMTRACKS:
	{
	    int cyl, cylsec, head, tracksec;
	    getchs (hfd, &cyl, &cylsec, &head, &tracksec);
	    actual = cyl * head;
	    break;
	}

	case CMD_GETGEOMETRY:
	{
	    int cyl, cylsec, head, tracksec;
	    getchs (hfd, &cyl, &cylsec, &head, &tracksec);
	    put_long (dataptr + 0, hfd->blocksize);
	    put_long (dataptr + 4, (uae_u32)(hfd->size / hfd->blocksize));
	    put_long (dataptr + 8, cyl);
	    put_long (dataptr + 12, cylsec);
	    put_long (dataptr + 16, head);
	    put_long (dataptr + 20, tracksec);
	    put_long (dataptr + 24, 0); /* bufmemtype */
	    put_byte (dataptr + 28, 0); /* type = DG_DIRECT_ACCESS */
	    put_byte (dataptr + 29, 0); /* flags */
	}
	break;

	case CMD_PROTSTATUS:
	    if (hfd->readonly)
		actual = -1;
	    else
		actual = 0;
	break;

	case CMD_CHANGESTATE:
	actual = 0;
	break;

	/* Some commands that just do nothing and return zero */
	case CMD_UPDATE:
	case CMD_CLEAR:
	case CMD_MOTOR:
	case CMD_SEEK:
	case TD_SEEK64:
	case NSCMD_TD_SEEK64:
	break;

	case CMD_REMOVE:
	break;

	case CMD_CHANGENUM:
	    actual = hfpd->changenum;
	break;

	case CMD_ADDCHANGEINT:
	error = add_async_request (hfpd, request, ASYNC_REQUEST_CHANGEINT, get_long (request + 40));
	if (!error)
	    async = 1;
	break;
	case CMD_REMCHANGEINT:
	release_async_request (hfpd, request);
	break;

	case HD_SCSICMD: /* SCSI */
	    if (hfd->nrcyls == 0) {
		error = handle_scsi (request, hfd);
	    } else { /* we don't want users trashing their "partition" hardfiles with hdtoolbox */
		error = -3; /* IOERR_NOCMD */
		write_log ("UAEHF: HD_SCSICMD tried on regular HDF, unit %d", unit);
	    }
	break;

	default:
	    /* Command not understood. */
	    error = -3; /* IOERR_NOCMD */
	break;
    }
    put_long (request + 32, actual);
    put_byte (request + 31, error);

    hf_log2 ("hf: unit=%d, request=%p, cmd=%d offset=%u len=%d, actual=%d error%=%d\n", unit, request,
	get_word (request + 28), get_long (request + 44), get_long (request + 36), actual, error);

    return async;
}

static uae_u32 REGPARAM2 hardfile_abortio (TrapContext *context)
{
    uae_u32 request = m68k_areg (&context->regs, 1);
    int unit = mangleunit (get_long (request + 24));
    struct hardfiledata *hfd = get_hardfile_data (unit);
    struct hardfileprivdata *hfpd = &hardfpd[unit];

    hf_log2 ("uaehf.device abortio ");
    start_thread(context, unit);
    if (!hfd || !hfpd || !hfpd->thread_running) {
	put_byte (request + 31, 32);
	hf_log2 ("error\n");
	return get_byte (request + 31);
    }
    put_byte (request + 31, -2);
    hf_log2 ("unit=%d, request=%08.8X\n",  unit, request);
    abort_async (hfpd, request, -2, 0);
    return 0;
}

static int hardfile_can_quick (uae_u32 command)
{
    switch (command)
    {
	case CMD_RESET:
	case CMD_STOP:
	case CMD_START:
	case CMD_CHANGESTATE:
	case CMD_PROTSTATUS:
	case CMD_MOTOR:
	case CMD_GETDRIVETYPE:
	case CMD_GETNUMTRACKS:
	case CMD_GETGEOMETRY:
	case NSCMD_DEVICEQUERY:
	return 1;
    }
    return 0;
}

static int hardfile_canquick (struct hardfiledata *hfd, uaecptr request)
{
    uae_u32 command = get_word (request + 28);
    return hardfile_can_quick (command);
}

static uae_u32 REGPARAM2 hardfile_beginio (TrapContext *context)
{
    uae_u32 request = m68k_areg (&context->regs, 1);
    uae_u8 flags = get_byte (request + 30);
    int cmd = get_word (request + 28);
    int unit = mangleunit (get_long (request + 24));
    struct hardfiledata *hfd = get_hardfile_data (unit);
    struct hardfileprivdata *hfpd = &hardfpd[unit];

    put_byte (request + 8, NT_MESSAGE);
    start_thread(context, unit);
    if (!hfd || !hfpd || !hfpd->thread_running) {
	put_byte (request + 31, 32);
	return get_byte (request + 31);
    }
    put_byte (request + 31, 0);
    if ((flags & 1) && hardfile_canquick (hfd, request)) {
	hf_log ("hf quickio unit=%d request=%p cmd=%d\n", unit, request, cmd);
	if (hardfile_do_io (hfd, hfpd, request))
	    hf_log2 ("uaehf.device cmd %d bug with IO_QUICK\n", cmd);
	return get_byte (request + 31);
    } else {
	hf_log2 ("hf asyncio unit=%d request=%p cmd=%d\n", unit, request, cmd);
	add_async_request (hfpd, request, ASYNC_REQUEST_TEMP, 0);
	put_byte (request + 30, get_byte (request + 30) & ~1);
	write_comm_pipe_u32 (&hfpd->requests, request, 1);
	return 0;
    }
}

static void *hardfile_thread (void *devs)
{
    struct hardfileprivdata *hfpd = (struct hardfileprivdata*)devs;

    uae_set_thread_priority (2);
    hfpd->thread_running = 1;
    uae_sem_post (&hfpd->sync_sem);
    for (;;) {
	uaecptr request = (uaecptr)read_comm_pipe_u32_blocking (&hfpd->requests);
	uae_sem_wait (&change_sem);
	if (!request) {
	    hfpd->thread_running = 0;
	    uae_sem_post (&hfpd->sync_sem);
	    uae_sem_post (&change_sem);
	    return 0;
	} else if (hardfile_do_io (get_hardfile_data (hfpd - &hardfpd[0]), hfpd, request) == 0) {
	    put_byte (request + 30, get_byte (request + 30) & ~1);
	    release_async_request (hfpd, request);
	    uae_ReplyMsg (request);
	} else {
	    hf_log2 ("async request %08.8X\n", request);
	}
	uae_sem_post (&change_sem);
    }
}

void hardfile_reset (void)
{
    int i, j;
    struct hardfileprivdata *hfpd;

    for (i = 0; i < MAX_FILESYSTEM_UNITS; i++) {
	 hfpd = &hardfpd[i];
	if (hfpd->base && valid_address(hfpd->base, 36) && get_word (hfpd->base + 32) > 0) {
	    for (j = 0; j < MAX_ASYNC_REQUESTS; j++) {
		uaecptr request;
		if ((request = hfpd->d_request[i]))
		    abort_async (hfpd, request, 0, 0);
	    }
	}
	memset (hfpd, 0, sizeof (struct hardfileprivdata));
    }
}

void hardfile_install (void)
{
    uae_u32 functable, datatable;
    uae_u32 initcode, openfunc, closefunc, expungefunc;
    uae_u32 beginiofunc, abortiofunc;

    uae_sem_init (&change_sem, 0, 1);

    ROM_hardfile_resname = ds ("uaehf.device");
    ROM_hardfile_resid = ds ("UAE hardfile.device 0.2");

    nscmd_cmd = here ();
    dw (NSCMD_DEVICEQUERY);
    dw (CMD_RESET);
    dw (CMD_READ);
    dw (CMD_WRITE);
    dw (CMD_UPDATE);
    dw (CMD_CLEAR);
    dw (CMD_START);
    dw (CMD_STOP);
    dw (CMD_FLUSH);
    dw (CMD_MOTOR);
    dw (CMD_SEEK);
    dw (CMD_FORMAT);
    dw (CMD_REMOVE);
    dw (CMD_CHANGENUM);
    dw (CMD_CHANGESTATE);
    dw (CMD_PROTSTATUS);
    dw (CMD_GETDRIVETYPE);
    dw (CMD_GETGEOMETRY);
    dw (CMD_ADDCHANGEINT);
    dw (CMD_REMCHANGEINT);
    dw (HD_SCSICMD);
    dw (NSCMD_TD_READ64);
    dw (NSCMD_TD_WRITE64);
    dw (NSCMD_TD_SEEK64);
    dw (NSCMD_TD_FORMAT64);
    dw (0);

    /* initcode */
#if 0
    initcode = here ();
    calltrap (deftrap (hardfile_init)); dw (RTS);
#else
    initcode = filesys_initcode;
#endif
    /* Open */
    openfunc = here ();
    calltrap (deftrap (hardfile_open)); dw (RTS);

    /* Close */
    closefunc = here ();
    calltrap (deftrap (hardfile_close)); dw (RTS);

    /* Expunge */
    expungefunc = here ();
    calltrap (deftrap (hardfile_expunge)); dw (RTS);

    /* BeginIO */
    beginiofunc = here ();
    calltrap (deftrap (hardfile_beginio));
    dw (RTS);

    /* AbortIO */
    abortiofunc = here ();
    calltrap (deftrap (hardfile_abortio)); dw (RTS);

    /* FuncTable */
    functable = here ();
    dl (openfunc); /* Open */
    dl (closefunc); /* Close */
    dl (expungefunc); /* Expunge */
    dl (EXPANSION_nullfunc); /* Null */
    dl (beginiofunc); /* BeginIO */
    dl (abortiofunc); /* AbortIO */
    dl (0xFFFFFFFFul); /* end of table */

    /* DataTable */
    datatable = here ();
    dw (0xE000); /* INITBYTE */
    dw (0x0008); /* LN_TYPE */
    dw (0x0300); /* NT_DEVICE */
    dw (0xC000); /* INITLONG */
    dw (0x000A); /* LN_NAME */
    dl (ROM_hardfile_resname);
    dw (0xE000); /* INITBYTE */
    dw (0x000E); /* LIB_FLAGS */
    dw (0x0600); /* LIBF_SUMUSED | LIBF_CHANGED */
    dw (0xD000); /* INITWORD */
    dw (0x0014); /* LIB_VERSION */
    dw (0x0004); /* 0.4 */
    dw (0xD000);
    dw (0x0016); /* LIB_REVISION */
    dw (0x0000);
    dw (0xC000);
    dw (0x0018); /* LIB_IDSTRING */
    dl (ROM_hardfile_resid);
    dw (0x0000); /* end of table */

    ROM_hardfile_init = here ();
    dl (0x00000100); /* ??? */
    dl (functable);
    dl (datatable);
    dl (initcode);
}

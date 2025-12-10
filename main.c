/*
 * 64kformat - format your memsticks goddammit
 *
 * This program is licensed under the GPL-v2 license.
 * https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html
 *
 * code from psp_pspident licensed under MIT.
 * https://opensource.org/licenses/MIT
 *
 * format code based on:
 * https://github.com/krazynez/psptool
 * https://github.com/ryansturmer/thinfat32/blob/master/src/thinfat32.c
 *
 * IF YOU PAID FOR THIS YOU'VE GOTTEN SCAMMED
 *
 * I hope she made LOTSA SPAGHETTI !
 */

#include "hwdetect.h"
#include "libpspexploit.h"
#include "partition_start.h"
#include "readme.h"
#include <fcntl.h>
#include <pspctrl.h>
#include <pspdebug.h>
#include <pspiofilemgr.h>
#include <pspkernel.h>
#include <pspsdk.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

PSP_MODULE_INFO("64kFormat", 0, 1, 1);
PSP_MAIN_THREAD_ATTR(THREAD_ATTR_USER | THREAD_ATTR_VFPU);

#define printf pspDebugScreenPrintf
#define RGB(r, g, b) ((r) | ((g) << 8) | ((b) << 16))

#define COL_ORANGE RGB(255, 165, 0)
#define COL_WHITE RGB(255, 255, 255)
#define COL_DARKGREY RGB(160, 160, 160)
#define COL_RED RGB(255, 0, 0)
#define COL_GREEN RGB(0, 255, 0)
#define COL_TRIANGLE RGB(68, 214, 44)
#define COL_CIRCLE RGB(255, 94, 94)
#define COL_CROSS RGB(92, 140, 245)
#define COL_SQUARE RGB(224, 104, 224)

const char *shapes[] = {"triangle", "circle", "cross", "square"};
const int shape_colors[] = {COL_TRIANGLE, COL_CIRCLE, COL_CROSS, COL_SQUARE};
const int btns[] = {PSP_CTRL_TRIANGLE, PSP_CTRL_CIRCLE, PSP_CTRL_CROSS,
                    PSP_CTRL_SQUARE};

int format_result = -1;
static unsigned long long stor_total = 0;
static unsigned long long stor_free = 0;
static unsigned int stor_cluster = 0;

static void getstorinfo(const char *dev) {
  u32 buf[5] = {0, 0, 0, 0, 0};
  u32 *pbuf = buf;
  stor_total = stor_free = 0ULL;
  stor_cluster = 0;
  if (sceIoDevctl(dev, 0x02425818, &pbuf, sizeof(pbuf), NULL, 0) >= 0) {
    stor_total = (unsigned long long)buf[0] * buf[3] * buf[4];
    stor_free = (unsigned long long)buf[1] * buf[3] * buf[4];
    stor_cluster = buf[3] * buf[4];
  }
}

static void LOG(const char *fmt, ...) {
  char _logbuf[512];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(_logbuf, sizeof(_logbuf), fmt, ap);
  va_end(ap);
  pspDebugScreenSetTextColor(COL_DARKGREY);
  pspDebugScreenPrintf("%s", _logbuf);
  pspDebugScreenSetTextColor(COL_WHITE);
}

static void fail_exit(const char *fmt, ...) {
  char _buf[512];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(_buf, sizeof(_buf), fmt, ap);
  va_end(ap);
  pspDebugScreenSetTextColor(COL_RED);
  printf("%s\n", _buf);
  sceKernelDelayThread(5000000);
  sceKernelExitGame();
}

static inline int MScmIsMediumInserted(void) {
  int status;
  int ret = sceIoDevctl("mscmhc0:", 0x02025806, 0, 0, &status, sizeof(status));
  if (ret < 0 || status != 1)
    return 0;
  return 1;
}

int exit_cb(int arg1, int arg2, void *common) {
  sceKernelExitGame();
  return 0;
}

int cb_thread(SceSize args, void *argp) {
  int cbid = sceKernelCreateCallback("Exit Callback", exit_cb, NULL);
  sceKernelRegisterExitCallback(cbid);
  sceKernelSleepThreadCB();
  return 0;
}

int do_format_ms(void) {

  /*
   *
   * https://download.microsoft.com/download/1/6/1/161ba512-40e2-4cc9-843a-923143f3456c/fatgen103.doc
   * https://elm-chan.org/docs/fat_e.html
   * https://wiki.osdev.org/FAT
   *
   */

  unsigned char mbr[512];
  unsigned char bootrecord[512];
  unsigned char *big_buffer;
  SceUID fd;
  int read_bytes;
  int old_partpreceed, old_partsize;
  int new_partpreceed, new_partsize, new_partclustersize;
  int new_partstartsize;

  LOG("fmt: start\n");

  /* 512-byte buffer sectors */
  new_partstartsize = partition_start_bin_len;
  if (new_partstartsize != (new_partstartsize / 512) * 512) {
    new_partstartsize = (new_partstartsize + 512) & 0xFFFFFE00;
  }

  big_buffer = malloc(new_partstartsize);
  if (!big_buffer) {
    LOG("malloc: fail\n");
    return -1;
  }
  memset(big_buffer, 0, new_partstartsize);
  memcpy(big_buffer, partition_start_bin, partition_start_bin_len);

  /* 0x00-0x0A: jump boot + OEM name */
  big_buffer[0] = 0xEB;
  big_buffer[1] = 0x58;
  big_buffer[2] = 0x90;
  memcpy(&big_buffer[3], "MSWIN4.1", 8);

  /* read existing MBR to get current partition info */
  fd = sceIoOpen("msstor:", PSP_O_RDONLY, 0777);
  if (fd < 0) {
    LOG("open rd: fail 0x%08x\n", fd);
    free(big_buffer);
    return -2;
  }

  read_bytes = sceIoRead(fd, mbr, 512);
  if (read_bytes != 512) {
    LOG("read mbr: fail rb=%d\n", read_bytes);
    sceIoClose(fd);
    free(big_buffer);
    return -3;
  }
  LOG("mbr: read\n");

  /* extract old partition LBA start from MBR entry */
  old_partpreceed = (mbr[454] & 0xFF) | ((mbr[455] & 0xFF) << 8) |
                    ((mbr[456] & 0xFF) << 16) | ((mbr[457] & 0xFF) << 24);

  /* read old boot sector to get partition size */
  sceIoLseek(fd, old_partpreceed * 512, PSP_SEEK_SET);
  read_bytes = sceIoRead(fd, bootrecord, 512);
  sceIoClose(fd);
  if (read_bytes != 512) {
    LOG("read boot: fail %d\n", old_partpreceed);
    free(big_buffer);
    return -4;
  }
  LOG("boot: read %d\n", old_partpreceed);

  /* extract old partition size from boot sector 0x20-0x23 */
  old_partsize = (bootrecord[32] & 0xFF) | ((bootrecord[33] & 0xFF) << 8) |
                 ((bootrecord[34] & 0xFF) << 16) |
                 ((bootrecord[35] & 0xFF) << 24);

  /* new partition */
  new_partpreceed = (250 * 2);
  new_partsize = old_partsize + old_partpreceed - new_partpreceed - 64;

  if (new_partsize <= 0) {
    LOG("partsize: invalid %d\n", new_partsize);
    free(big_buffer);
    return -8;
  }
  if (new_partpreceed < 16 ||
      new_partpreceed > old_partpreceed + old_partsize) {
    LOG("partpreceed: range %d\n", new_partpreceed);
    free(big_buffer);
    return -9;
  }

  /* 64KB cluster size = 128 sectors */
  new_partclustersize = 128;

  /* 0x0B-0x0C: bytes per sector = 512 */
  big_buffer[11] = 0x00;
  big_buffer[12] = 0x02;

  /* 0x0D: sectors per cluster */
  big_buffer[13] = new_partclustersize;

  /* 0x15: media descriptor = 0xF8 (hard disk) */
  big_buffer[21] = 0xF8;

  /* 0x18-0x19: sectors per track = 63 */
  big_buffer[24] = 0x3F;
  big_buffer[25] = 0x00;

  /* 0x1A-0x1B: heads = 255 */
  big_buffer[26] = 0xFF;
  big_buffer[27] = 0x00;

  /* 0x1C-0x1F: hidden sectors (partition LBA start) */
  big_buffer[28] = new_partpreceed & 0xFF;
  big_buffer[29] = (new_partpreceed >> 8) & 0xFF;
  big_buffer[30] = (new_partpreceed >> 16) & 0xFF;
  big_buffer[31] = (new_partpreceed >> 24) & 0xFF;

  {
    unsigned long long total_sectors = (unsigned long long)new_partsize;
    unsigned long long sectors_per_cluster =
        (unsigned long long)new_partclustersize;
    const unsigned long long bytes_per_sector = 512ULL;
    const unsigned long long reserved_sectors = 32ULL;
    const unsigned long long num_fats = 2ULL;
    unsigned long long sectors_per_fat = 0ULL;
    unsigned long long data_sectors = 0ULL;
    unsigned long long cluster_count = 0ULL;
    int want_fat32 = 0;

    /* sectors */
    const unsigned long long fat_element_size = 4ULL;
    unsigned long long numerator =
        fat_element_size * (total_sectors - reserved_sectors);
    unsigned long long denominator = (sectors_per_cluster * bytes_per_sector) +
                                     (fat_element_size * num_fats);
    sectors_per_fat = (numerator / denominator) + 1ULL;

    for (int iter = 0; iter < 8; ++iter) {
      data_sectors =
          total_sectors - reserved_sectors - (num_fats * sectors_per_fat);
      cluster_count = data_sectors / sectors_per_cluster;

      unsigned long long fat_needed =
          (cluster_count * fat_element_size + (bytes_per_sector - 1)) /
          bytes_per_sector;
      if (fat_needed > sectors_per_fat) {
        sectors_per_fat = fat_needed;
        continue;
      }
      break;
    }

    /* validate cluster count (65525 - 268435455) */
    if (cluster_count > 0x0FFFFFFF) {
      LOG("cluster count too high: %llu\n", cluster_count);
      free(big_buffer);
      return -20;
    }
    if (cluster_count < 65536) {
      LOG("cluster count too low: %llu\n", cluster_count);
      free(big_buffer);
      return -21;
    }

    want_fat32 = 1;

    /* MBR partition entry (0x1BE): boot indicator + CHS start */
    mbr[446] = 0x80;
    mbr[447] = 0xFF;
    mbr[448] = 0xFF;
    mbr[449] = 0xFF;

    /* MBR: partition type 0x0C (FAT32 LBA) + CHS end */
    mbr[450] = 0x0C;
    mbr[451] = 0xFF;
    mbr[452] = 0xFF;
    mbr[453] = 0xFF;

    /* MBR: LBA start */
    mbr[454] = new_partpreceed & 0xFF;
    mbr[455] = (new_partpreceed >> 8) & 0xFF;
    mbr[456] = (new_partpreceed >> 16) & 0xFF;
    mbr[457] = (new_partpreceed >> 24) & 0xFF;

    /* MBR: partition size in sectors */
    mbr[458] = new_partsize & 0xFF;
    mbr[459] = (new_partsize >> 8) & 0xFF;
    mbr[460] = (new_partsize >> 16) & 0xFF;
    mbr[461] = (new_partsize >> 24) & 0xFF;

    /* MBR: boot signature */
    mbr[510] = 0x55;
    mbr[511] = 0xAA;

    if (want_fat32) {
      unsigned int spf = (unsigned int)sectors_per_fat;

      /* 0x0E-0x0F: reserved sectors = 32 */
      big_buffer[14] = 0x20;
      big_buffer[15] = 0x00;

      /* 0x10: number of FATs = 2 */
      big_buffer[16] = 0x02;

      /* 0x11-0x12: root entries = 0 (must be 0 for FAT32) */
      big_buffer[17] = 0x00;
      big_buffer[18] = 0x00;

      /* 0x13-0x14: total sectors 16-bit = 0 (must be 0 for FAT32) */
      big_buffer[19] = 0x00;
      big_buffer[20] = 0x00;

      /* 0x16-0x17: sectors per FAT 16-bit = 0 (must be 0 for FAT32) */
      big_buffer[22] = 0x00;
      big_buffer[23] = 0x00;

      /* 0x20-0x23: total sectors 32-bit */
      big_buffer[32] = new_partsize & 0xFF;
      big_buffer[33] = (new_partsize >> 8) & 0xFF;
      big_buffer[34] = (new_partsize >> 16) & 0xFF;
      big_buffer[35] = (new_partsize >> 24) & 0xFF;

      /* 0x24-0x27: sectors per FAT (FAT32) */
      big_buffer[36] = spf & 0xFF;
      big_buffer[37] = (spf >> 8) & 0xFF;
      big_buffer[38] = (spf >> 16) & 0xFF;
      big_buffer[39] = (spf >> 24) & 0xFF;

      /* 0x28-0x29: ext flags = 0 (FAT mirroring enabled) */
      big_buffer[40] = 0x00;
      big_buffer[41] = 0x00;

      /* 0x2A-0x2B: filesystem version = 0.0 */
      big_buffer[42] = 0x00;
      big_buffer[43] = 0x00;

      /* 0x2C-0x2F: root directory first cluster = 2 */
      big_buffer[44] = 0x02;
      big_buffer[45] = 0x00;
      big_buffer[46] = 0x00;
      big_buffer[47] = 0x00;

      /* 0x30-0x31: FSInfo sector number = 1 */
      big_buffer[48] = 0x01;
      big_buffer[49] = 0x00;

      /* 0x32-0x33: backup boot sector = 6 */
      big_buffer[50] = 0x06;
      big_buffer[51] = 0x00;

      /* 0x34-0x3F: reserved (12 bytes) */
      memset(&big_buffer[52], 0, 12);

      /* 0x40: drive number = 0x80 (hard disk) */
      big_buffer[64] = 0x80;

      /* 0x41: reserved (NT flags) */
      big_buffer[65] = 0x00;

      /* 0x42: extended boot signature = 0x29 */
      big_buffer[66] = 0x29;

      /* 0x43-0x46: volume serial number */
      unsigned int vid = rand();
      big_buffer[67] = vid & 0xFF;
      big_buffer[68] = (vid >> 8) & 0xFF;
      big_buffer[69] = (vid >> 16) & 0xFF;
      big_buffer[70] = (vid >> 24) & 0xFF;

      if (new_partstartsize < 512 + 72) {
        LOG("buffer too small!\n");
        free(big_buffer);
        return -22;
      }

      /* 0x47-0x51: volume label */
      memcpy(&big_buffer[71], "NO NAME    ", 11);

      /* 0x52-0x59: filesystem type string */
      memcpy(&big_buffer[82], "FAT32   ", 8);

      /* 0x1FE-0x1FF: boot sector signature */
      big_buffer[510] = 0x55;
      big_buffer[511] = 0xAA;

      /* sector 1: FSInfo structure */
      memset(&big_buffer[512], 0, 512);

      /* FSInfo 0x000-0x003: lead signature "RRaA" */
      *((unsigned int *)&big_buffer[512 + 0]) = 0x41615252;

      /* FSInfo 0x1E4-0x1E7: structure signature "rrAa" */
      *((unsigned int *)&big_buffer[512 + 0x1E4]) = 0x61417272;

      /* FSInfo 0x1E8-0x1EB: free cluster count */
      unsigned int free_count = (unsigned int)cluster_count - 1;
      *((unsigned int *)&big_buffer[512 + 0x1E8]) = free_count;

      /* FSInfo 0x1EC-0x1EF: next free cluster hint */
      *((unsigned int *)&big_buffer[512 + 0x1EC]) = 0x00000003;

      /* FSInfo 0x1FC-0x1FF: trail signature */
      *((unsigned int *)&big_buffer[512 + 0x1FC]) = 0xAA550000;

      /* sectors 2-5: zeroed */
      memset(&big_buffer[1024], 0, 2048);

      /* sector 6: backup boot sector */
      memcpy(&big_buffer[3072], &big_buffer[0], 512);

      /* sector 7: backup FSInfo */
      memcpy(&big_buffer[3584], &big_buffer[512], 512);

      /* sector 8: zeroed */
      memset(&big_buffer[4096], 0, 512);

      /* sectors 9-31: reserved area, zeroed */
      memset(&big_buffer[4608], 0, 16384 - 4608);

      /* sector 32: FAT table start */
      memset(&big_buffer[16384], 0, 512);
      int fat_offset = 16384;

      /* FAT[0]: media descriptor + EOF mark */
      *((unsigned int *)&big_buffer[fat_offset]) = 0x0FFFFFF8;

      /* FAT[1]: end of chain marker */
      *((unsigned int *)&big_buffer[fat_offset + 4]) = 0x0FFFFFFF;

      /* FAT[2]: root directory end of chain */
      *((unsigned int *)&big_buffer[fat_offset + 8]) = 0x0FFFFFFF;

      /* validate cluster size */
      if (new_partclustersize != 128) {
        LOG("Invalid sectors per cluster: %d\n", new_partclustersize);
        new_partclustersize = 128;
      }
      big_buffer[13] = new_partclustersize;

      LOG("part: pre=%d size=%d cls=0x%02x cnt=%llu spf=%llu fat32=%d\n",
          new_partpreceed, new_partsize, new_partclustersize, cluster_count,
          sectors_per_fat, want_fat32);
    }
  }

  sceIoUnassign("ms0:");
  LOG("ms0: unassigned\n");
  sceKernelDelayThread(2000000);

  /* write MBR and parts */
  LOG("writing...\n");
  fd = sceIoOpen("msstor:", PSP_O_RDWR, 0777);
  if (fd < 0) {
    LOG("open wr: fail 0x%08x\n", fd);
    free(big_buffer);
    return -10;
  }

  /* write MBR (sector 0) */
  int written = sceIoWrite(fd, mbr, 512);
  if (written != 512) {
    LOG("write mbr: fail %d\n", written);
    sceIoClose(fd);
    free(big_buffer);
    return -11;
  }

  int seeked = sceIoLseek(fd, new_partpreceed * 512, PSP_SEEK_SET);
  if (seeked != new_partpreceed * 512) {
    LOG("seek: fail\n");
    sceIoClose(fd);
    free(big_buffer);
    return -12;
  }

  /* boot sector + reserved and FAT */
  {
    const int CHUNK = 4096;
    int to_write = new_partstartsize;
    unsigned char *p = (unsigned char *)big_buffer;
    int off = 0;
    while (to_write > 0) {
      int this_chunk = (to_write > CHUNK) ? CHUNK : to_write;
      int wrote = 0;
      while (wrote < this_chunk) {
        int r = sceIoWrite(fd, p + off + wrote, this_chunk - wrote);
        if (r < 0) {
          LOG("write chunk: fail off=%d err=0x%08x\n", off + wrote, r);
          sceIoClose(fd);
          free(big_buffer);
          return -13;
        }
        wrote += r;
      }
      off += this_chunk;
      to_write -= this_chunk;
      if ((off & 0x7FFF) == 0)
        sceKernelDelayThread(20000);
    }
  }

  sceIoSync("msstor:", 0);
  sceKernelDelayThread(1000000);
  sceIoClose(fd);

  fd = sceIoOpen("msstor:", PSP_O_RDONLY, 0777);
  if (fd < 0) {
    LOG("verify open: fail 0x%08x\n", fd);
    free(big_buffer);
    return -14;
  }

  unsigned char verify_mbr[512];
  read_bytes = sceIoRead(fd, verify_mbr, 512);
  if (read_bytes == 512 && memcmp(verify_mbr, mbr, 512) == 0) {
    LOG("mbr: OK\n");
  } else {
    LOG("mbr: fail\n");
    sceIoClose(fd);
    free(big_buffer);
    return -15;
  }

  sceIoLseek(fd, new_partpreceed * 512, PSP_SEEK_SET);
  {
    const int RCHK = 4096;
    int remaining = new_partstartsize;
    unsigned char *p = (unsigned char *)big_buffer;
    int off = 0;
    int mismatch = 0;
    while (remaining > 0) {
      int want = (remaining > RCHK) ? RCHK : remaining;
      unsigned char rbuf[4096];
      int r = sceIoRead(fd, rbuf, want);
      if (r != want) {
        LOG("read part: fail off=%d r=%d want=%d\n", off, r, want);
        sceIoClose(fd);
        free(big_buffer);
        return -16;
      }
      if (memcmp(rbuf, p + off, want) != 0) {
        for (int i = 0; i < want; i++) {
          if (rbuf[i] != p[off + i]) {
            int sector = (new_partpreceed * 512 + off + i) / 512;
            int byteoff = (new_partpreceed * 512 + off + i) % 512;
            LOG("mismatch: abs=%d sec=%d byte=%d r=0x%02x e=0x%02x\n", off + i,
                sector, byteoff, rbuf[i], p[off + i]);
            mismatch = 1;
            break;
          }
        }
        if (mismatch)
          break;
      }
      off += want;
      remaining -= want;
    }
    if (mismatch) {
      LOG("part: fail\n");
      sceIoClose(fd);
      free(big_buffer);
      return -16;
    }
    LOG("part: OK\n");
  }

  sceIoClose(fd);
  free(big_buffer);
  LOG("done\n");
  return 0;
}

void create_default_dirs(void) {
  // ark4 dirs cus tk asked
  // idk
  LOG("dirs: create\n");
  const char *dirs[] = {"ms0:/ISO",
                        "ms0:/ISO/VIDEO",
                        "ms0:/MUSIC",
                        "ms0:/PICTURE",
                        "ms0:/VIDEO",
                        "ms0:/SEPLUGINS",
                        "ms0:/MP_ROOT",
                        "ms0:/MP_ROOT/100MNV01",
                        "ms0:/MP_ROOT/101ANV01",
                        "ms0:/PSP",
                        "ms0:/PSP/COMMON",
                        "ms0:/PSP/GAME",
                        "ms0:/PSP/RSSCH",
                        "ms0:/PSP/RSSCH/IMPORT",
                        "ms0:/PSP/SAVEDATA",
                        "ms0:/PSP/SAVEDATA/ARK_01234",
                        "ms0:/PSP/SYSTEM",
                        "ms0:/PSP/THEME"};
  for (int i = 0; i < sizeof(dirs) / sizeof(dirs[0]); i++) {
    int res = sceIoMkdir(dirs[i], 0777);
    LOG("mkdir %s: 0x%08x\n", dirs[i], res);
    sceIoSync("ms0:", 0);
  }
  const char *files[] = {"ms0:/SEPLUGINS/plugins.txt"};
  for (int i = 0; i < sizeof(files) / sizeof(files[0]); i++) {
    SceUID fd =
        sceIoOpen(files[i], PSP_O_WRONLY | PSP_O_CREAT | PSP_O_TRUNC, 0777);
    if (fd >= 0) {
      LOG("file %s: fd=0x%08x\n", files[i], fd);
      sceIoClose(fd);
      sceIoSync("ms0:", 0);
    } else {
      LOG("file %s: fail 0x%08x\n", files[i], fd);
    }
  }
  SceUID fd = sceIoOpen("ms0:/readme.txt",
                        PSP_O_WRONLY | PSP_O_CREAT | PSP_O_TRUNC, 0777);
  if (fd >= 0) {
    LOG("readme: writing fd=0x%08x\n", fd);
    sceIoWrite(fd, readme_text, strlen(readme_text));
    sceIoClose(fd);
    sceIoSync("ms0:", 0);
  } else {
    LOG("readme: fail 0x%08x\n", fd);
  }
}

int read_firmware_version(char *out, int outlen) {
  char buf[1024];
  SceUID fd = sceIoOpen("flash0:/vsh/etc/version.txt", PSP_O_RDONLY, 0777);
  if (fd < 0) {
    out[0] = '\0';
    return -1;
  }
  int r = sceIoRead(fd, buf, sizeof(buf) - 1);
  sceIoClose(fd);
  if (r <= 0) {
    out[0] = '\0';
    return -1;
  }
  buf[r] = '\0';
  char *p = strstr(buf, "release:");
  if (p) {
    p += strlen("release:");
    char *q = strchr(p, ':');
    if (!q)
      q = strchr(p, '\n');
    if (!q)
      q = p + strlen(p);
    int len = q - p;
    if (len > outlen - 1)
      len = outlen - 1;
    memcpy(out, p, len);
    out[len] = '\0';
    return 0;
  }
  out[0] = '\0';
  return -1;
}

int main(int argc, char *argv[]) {
  pspDebugScreenInit();
  printf("loading...\n");

  int thid =
      sceKernelCreateThread("update_thread", cb_thread, 0x11, 0xFA0, 0, 0);
  if (thid >= 0)
    sceKernelStartThread(thid, 0, 0);

  LOG("init...\n");
  int res = pspXploitInitKernelExploit();
  if (res == 0) {
    LOG("init: OK\n");
    LOG("triggering...\n");
    res = pspXploitDoKernelExploit();
    if (res == 0) {
      LOG("exploit: OK!\n");
      hwdetect_run();
      LOG("helper: done\n");
    } else {
      LOG("exploit: fail 0x%08x\n", res);
    }
  } else {
    LOG("init: fail 0x%08x\n", res);
  }

  if (res < 0) {
    fail_exit("failed: exploit: 0x%08x", res);
    return 0;
  }

  if (strstr(hw_model, "PSP-N10") != NULL) {
    fail_exit("failed: pspgo");
    return 0;
  }

  pspDebugScreenSetTextColor(COL_ORANGE);
  printf("64kformat " __DATE__ " " __TIME__ "\n");
  pspDebugScreenSetTextColor(COL_DARKGREY);
  printf("https://the-sauna.icu/64kformat/\n\n");
  pspDebugScreenSetTextColor(COL_WHITE);
  printf("psp model detected: %s\n", hw_model);
  char fwver[64];
  if (read_firmware_version(fwver, sizeof(fwver)) == 0 && fwver[0]) {
    pspDebugScreenSetTextColor(COL_WHITE);
    printf("firmware: %s\n", fwver);
  } else {
    pspDebugScreenSetTextColor(COL_WHITE);
    printf("firmware: unknown\n");
  }
  pspDebugScreenSetTextColor(COL_DARKGREY);
  printf("------------------------------\n\n");
  pspDebugScreenSetTextColor(COL_RED);
  printf("warning: all data on the memory stick will be lost!\n\n");

  {
    u32 seed = (u32)sceKernelLibcTime(NULL);
    srand(seed);
  }
  int code[6];
  int input_idx = 0;
  SceCtrlData pad;

  while (1) {
    pspDebugScreenSetTextColor(COL_WHITE);
    printf("to confirm format, enter the following code:\n\n");
    for (int i = 0; i < 6; i++) {
      code[i] = rand() % 4;
      pspDebugScreenSetTextColor(shape_colors[code[i]]);
      printf("%s ", shapes[code[i]]);
    }
    pspDebugScreenSetTextColor(COL_WHITE);
    printf("\n\n");
    input_idx = 0;
    while (input_idx < 6) {
      sceCtrlReadBufferPositive(&pad, 1);
      if (pad.Buttons) {
        int btn = -1;
        if (pad.Buttons & PSP_CTRL_TRIANGLE)
          btn = 0;
        else if (pad.Buttons & PSP_CTRL_CIRCLE)
          btn = 1;
        else if (pad.Buttons & PSP_CTRL_CROSS)
          btn = 2;
        else if (pad.Buttons & PSP_CTRL_SQUARE)
          btn = 3;
        if (btn != -1) {
          while (pad.Buttons)
            sceCtrlReadBufferPositive(&pad, 1);
          pspDebugScreenSetTextColor(shape_colors[btn]);
          printf("* ");
          if (btn != code[input_idx]) {
            pspDebugScreenSetTextColor(COL_RED);
            printf("\n\nincorrect code! retrying...\n\n");
            break;
          }
          input_idx++;
        }
      }
    }
    if (input_idx == 6)
      break;
  }

  pspDebugScreenSetTextColor(COL_ORANGE);
  printf("\n\ncode confirmed. formatting...\n");

  format_result = do_format_ms();

  if (format_result < 0) {
    fail_exit("failed: format: %d", format_result);
  } else {
    pspDebugScreenSetTextColor(COL_GREEN);
    printf("format successful!\n");
    sceIoSync("msstor:", 0);
    sceKernelDelayThread(500000);
    int stop_res = sceIoDevctl("msstor:", 0x02415821, NULL, 0, NULL, 0);
    LOG("msstor stop: 0x%08x\n", stop_res);
    sceKernelDelayThread(1500000);
    pspDebugScreenSetTextColor(COL_RED);
    printf("please remove and re-insert the memory stick, then press x.\n");
    SceCtrlData pad;
    do {
      sceCtrlReadBufferPositive(&pad, 1);
    } while (!(pad.Buttons & PSP_CTRL_CROSS));
    sceKernelDelayThread(500000);
    while (!MScmIsMediumInserted()) {
      sceKernelDelayThread(100000);
    }
    pspDebugScreenSetTextColor(COL_DARKGREY);
    printf("memory detected...\n");
    sceKernelDelayThread(3000000);
    int res =
        sceIoAssign("ms0:", "msstor0p1:", "fatms0:", IOASSIGN_RDWR, NULL, 0);
    if (res < 0) {
      fail_exit("failed: assign: 0x%08x", res);
    } else {
      LOG("assign: OK\n");
      sceKernelDelayThread(200000);
      getstorinfo("ms0:");
      LOG("cluster=%u total=%llu free=%llu\n", stor_cluster, stor_total,
          stor_free);
      if (stor_cluster != (64U * 1024U)) {
        fail_exit("failed: cluster: %u (expected 65536)", stor_cluster);
      }
      pspDebugScreenSetTextColor(COL_GREEN);
      printf("creating default directories...\n");
      create_default_dirs();
      printf("directories created.\n");
    }
    pspDebugScreenSetTextColor(COL_GREEN);
    printf("format complete. exiting in 5...\n");
    sceKernelDelayThread(5000000);
    sceIoSync("msstor:", 0);
    sceIoUnassign("ms0:");
    sceKernelDelayThread(200000);
    sceKernelExitGame();
  }
  return 0;
}

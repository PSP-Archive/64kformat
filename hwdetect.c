#include "hwdetect.h"
#include "libpspexploit.h"
#include <pspkernel.h>
#include <pspsysmem_kernel.h>
#include <stdio.h>
#include <string.h>

static int ModelRegion[16] = {0, 0, 0, 0, 1, 4, 5, 3, 10, 2, 6, 7, 8, 9, 0, 0};

char hw_model[64];
int hw_tachyon;
int hw_baryon;
int hw_pommel;

static KernelFunctions _ktbl;
static KernelFunctions *k_tbl = &_ktbl;

static int (*_sceSysregGetTachyonVersion)(void) = NULL;
static int (*_sceSysconGetBaryonVersion)(int *) = NULL;
static int (*_sceSysconGetPommelVersion)(int *) = NULL;
static int (*_sceIdStorageLookup)(int, int, void *, int) = NULL;
static int (*_sceKernelGetModel)(void) = NULL;
static int (*_sceKernelDelayThread)(int) = NULL;
static int (*_sceKernelExitDeleteThread)(int) = NULL;

static inline u32 findGetModel(void) {
  u32 addr;
  for (addr = 0x88000000; addr < 0x88400000; addr += 4) {
    u32 data = _lw(addr);
    if (data == 0x3C03BC10) {
      return pspXploitFindFirstJALReverse(addr);
    }
  }
  return 0;
}

static inline int prxKernelGetModel(void) {
  int k1 = pspSdkSetK1(0);
  int g = _sceKernelGetModel();
  pspSdkSetK1(k1);
  return g;
}

static inline int prxSysregGetTachyonVersion(void) {
  int k1 = pspSdkSetK1(0);
  int sv = _sceSysregGetTachyonVersion();
  pspSdkSetK1(k1);
  return sv;
}

static int kthread(void) {
  char region[2];
  int generation;

  _sceSysconGetBaryonVersion(&hw_baryon);
  _sceSysconGetPommelVersion(&hw_pommel);
  hw_tachyon = prxSysregGetTachyonVersion();

  memset(region, 0, sizeof(region));
  _sceIdStorageLookup(0x0100, 0xF5, &region, 1);
  generation = prxKernelGetModel() + 1;

  memset(hw_model, 0, sizeof(hw_model));

  switch (hw_tachyon) {
  case 0x00140000:
    sprintf(hw_model, "PSP-10%02i TA-079", ModelRegion[(int)region[0]]);
    break;

  case 0x00200000:
    sprintf(hw_model, "PSP-10%02i TA-079v4/5", ModelRegion[(int)region[0]]);
    break;

  case 0x00300000:
    sprintf(hw_model, "PSP-10%02i TA-081", ModelRegion[(int)region[0]]);
    break;

  case 0x00400000:
    if (hw_baryon == 0x00114000)
      sprintf(hw_model, "PSP-10%02i TA-082", ModelRegion[(int)region[0]]);
    else if (hw_baryon == 0x00121000)
      sprintf(hw_model, "PSP-10%02i TA-086", ModelRegion[(int)region[0]]);
    else
      sprintf(hw_model, "PSP-10%02i TA-08x", ModelRegion[(int)region[0]]);
    break;

  case 0x00500000:
    if (hw_baryon == 0x0022B200 || hw_baryon == 0x00234000)
      sprintf(hw_model, "PSP-20%02i TA-085", ModelRegion[(int)region[0]]);
    else if (hw_baryon == 0x00243000)
      sprintf(hw_model, "PSP-20%02i TA-088", ModelRegion[(int)region[0]]);
    else
      sprintf(hw_model, "PSP-20%02i TA-0xx", ModelRegion[(int)region[0]]);
    break;

  case 0x00600000:
    if (hw_baryon == 0x00243000)
      sprintf(hw_model, "PSP-20%02i TA-088v3", ModelRegion[(int)region[0]]);
    else if (hw_baryon == 0x00263100)
      sprintf(hw_model, "PSP-30%02i TA-090", ModelRegion[(int)region[0]]);
    else if (hw_baryon == 0x00285000)
      sprintf(hw_model, "PSP-30%02i TA-092", ModelRegion[(int)region[0]]);
    else
      sprintf(hw_model, "PSP-x0%02i TA-0xx", ModelRegion[(int)region[0]]);
    break;

  case 0x00720000:
    sprintf(hw_model, "PSP-N10%02i TA-091", ModelRegion[(int)region[0]]);
    break;

  case 0x00810000:
    if (hw_baryon == 0x002C4000)
      sprintf(hw_model, "PSP-30%02i TA-093", ModelRegion[(int)region[0]]);
    else if (hw_baryon == 0x002E4000 || hw_baryon == 0x012E4000)
      sprintf(hw_model, "PSP-30%02i TA-095", ModelRegion[(int)region[0]]);
    else if (hw_baryon == 0x00323100 || hw_baryon == 0x00324000)
      sprintf(hw_model, "PSP-N10%02i TA-094", ModelRegion[(int)region[0]]);
    else
      sprintf(hw_model, "PSP-x0%02i TA-09x", ModelRegion[(int)region[0]]);
    break;

  case 0x00820000:
    sprintf(hw_model, "PSP-30%02i TA-095", ModelRegion[(int)region[0]]);
    break;

  case 0x00900000:
    sprintf(hw_model, "PSP-E10%02i TA-096/097", ModelRegion[(int)region[0]]);
    break;

  default:
    sprintf(hw_model, "PSP (%02ig)", generation);
    break;
  }

  char gen_str[16];
  sprintf(gen_str, " (%02ig)", generation);
  strcat(hw_model, gen_str);

  _sceKernelDelayThread(100000);
  _sceKernelExitDeleteThread(0);
  return 0;
}

static void kmain(void) {
  int k1 = pspSdkSetK1(0);
  int userlevel = pspXploitSetUserLevel(8);

  pspXploitRepairKernel();
  pspXploitScanKernelFunctions(k_tbl);

  char *sysreg_mod = (pspXploitFindTextAddrByName("sceLowIO_Driver") == 0)
                         ? "sceSYSREG_Driver"
                         : "sceLowIO_Driver";

  _sceSysregGetTachyonVersion =
      (void *)pspXploitFindFunction(sysreg_mod, "sceSysreg_driver", 0xE2A5D1EE);
  _sceSysconGetBaryonVersion = (void *)pspXploitFindFunction(
      "sceSYSCON_Driver", "sceSyscon_driver", 0x7EC5A957);
  _sceSysconGetPommelVersion = (void *)pspXploitFindFunction(
      "sceSYSCON_Driver", "sceSyscon_driver", 0xE7E87741);
  _sceIdStorageLookup = (void *)pspXploitFindFunction(
      "sceIdStorage_Service", "sceIdStorage_driver", 0x6FE062D1);
  _sceKernelGetModel = (void *)findGetModel();
  _sceKernelDelayThread = (void *)pspXploitFindFunction(
      "sceThreadManager", "ThreadManForUser", 0xCEADEB47);
  _sceKernelExitDeleteThread = (void *)pspXploitFindFunction(
      "sceThreadManager", "ThreadManForUser", 0x809CE29B);

  SceUID kthreadID =
      k_tbl->KernelCreateThread("hwdetect_kthread", (void *)KERNELIFY(&kthread),
                                1, 0x10000, PSP_THREAD_ATTR_VFPU, NULL);
  if (kthreadID >= 0) {
    k_tbl->KernelStartThread(kthreadID, 0, NULL);
    k_tbl->waitThreadEnd(kthreadID, NULL);
  }

  pspXploitSetUserLevel(userlevel);
  pspSdkSetK1(k1);
}

void hwdetect_run(void) { pspXploitExecuteKernel((u32)kmain); }

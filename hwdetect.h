#ifndef HWDETECT_H
#define HWDETECT_H

#define TACHYON_0x00140000 0x00140000
#define TACHYON_0x00200000 0x00200000
#define TACHYON_0x00300000 0x00300000
#define TACHYON_0x00400000 0x00400000
#define TACHYON_0x00500000 0x00500000
#define TACHYON_0x00600000 0x00600000
#define TACHYON_0x00720000 0x00720000
#define TACHYON_0x00810000 0x00810000
#define TACHYON_0x00820000 0x00820000
#define TACHYON_0x00900000 0x00900000

extern char hw_model[64];
extern int hw_tachyon;
extern int hw_baryon;
extern int hw_pommel;

void hwdetect_run(void);

#endif

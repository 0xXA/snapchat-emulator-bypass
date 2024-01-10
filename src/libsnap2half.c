/*
 * Copyright (C) 2024 Yuvraj Saxena <ysaxenax@gmail.com>
 */

#include <android/log.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <libgen.h>
#include <math.h>
#include <sys/stat.h>
#include <sys/auxv.h>
#include <sys/system_properties.h>

#ifdef X86
#include "../x86/frida-gum.h"
#elif defined X64
#include "../x64/frida-gum.h"
#elif defined ARM
#include "../arm/frida-gum.h"
#elif defined ARM64
#include "../arm64/frida-gum.h"
#else
#error "unsupported platform"
#endif

//#define MOBILE // Disable it for emulator builds

#ifdef X86
#define THISLIB "libsnap2half_x86"
#elif defined X64
#define THISLIB "libsnap2half_x64"
#elif defined ARM
#define THISLIB "libsnap2half_arm"
#elif defined ARM64
#define THISLIB "libsnap2half_arm64"
#endif

#ifdef LOGTOFILE
  static FILE *logfile;
#endif
static FILE* cpuinfoptr;
static unsigned long openataddr;

#define GUM_PAGE_X ((GumPageProtection) (GUM_PAGE_EXECUTE))

//static unsigned long call_array;
typedef struct _ExampleListener ExampleListener;
typedef enum _ExampleHookId ExampleHookId;

struct _ExampleListener {
  GObject parent;
};

enum _ExampleHookId {
  HOOK_CALL_ARRAY
};

static void example_listener_iface_init (gpointer g_iface, gpointer iface_data);

#define EXAMPLE_TYPE_LISTENER (example_listener_get_type ())
G_DECLARE_FINAL_TYPE (ExampleListener, example_listener, EXAMPLE, LISTENER, GObject)
G_DEFINE_TYPE_EXTENDED (ExampleListener,
                        example_listener,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_INVOCATION_LISTENER,
                            example_listener_iface_init))

#define VSSCANF(expr) \
    va_list ap; \
    va_start(ap, fmt); \
    int result = (expr); \
    va_end(ap); \
    return result;

static char *brand_table[] = {
        "Redmi",
        "Meizu",
        "Mi",
};
static char *brand;
#define BRAND_TABLE_SIZE 3

static char *release_table[] = {
        "9",
        "10",
        "11",
        "12"
};
static char *release;
#define RELEASE_TABLE_SIZE 4

static char *operator_alpha_table[] = {
        ",CellOne",
        ",Airtel",
        ",Idea",
        ",Vodafone",
        ",Jio"
};
#define OPERATOR_ALPHA_TABLE_SIZE 5

static char *hardware_table[] = {
        "MT6769Z",
        "MT6789P",
        "MT6795E",
        "MT6796Z"
};
#define HARDWARE_TABLE_SIZE 4

static char *hardware_table1[] = {
        "mt6765",
        "mt6766",
        "mt6767",
        "mt6768",
        "mt6789",
        "mt6796"
};

#define HARDWARE1_TABLE_SIZE 6

static char *product_table[] = {
        "juliet",
        "RMX2027",
        "lavender",
        "dragon",
        "dandellion",
        "rosy",
        "miatoll",
        "rmx",
        "mido"
};

static char *product;
#define PRODUCT_TABLE_SIZE 9

static char serialno[13]; // buffer to hold random serial no
static char android_id[0x11]; // buffer to hold random serial no
static char *new_hardware; // pointer to hold random hardware 
static char fingerprint[120]; // buffer to hold random build fingerprint

/*
 * Copied from glibc in case if i wanted to hook these function in future i will just use
 * my own copied versions.
 */
__attribute__((always_inline)) static inline int my_strncmp(const char *s1, const char *s2, size_t n) {
    if (n == 0) return 0;
    do {
        if (*s1 != *s2++) return (*(unsigned char *)s1 - *(unsigned char *)--s2);
        if (*s1++ == 0) break;
    } while (--n != 0);
    return 0;
}

__attribute__((always_inline)) static inline size_t my_strlen(const char *s) {
    size_t len = 0;
    if(s==NULL) return 0;
    while(*s++) len++;
    return len;
}

__attribute__((always_inline)) static inline int my_strcmp(const char *s1, const char *s2) {
    if(s1==NULL||s2==NULL) return 1;
    while (*s1 == *s2++) if (*s1++ == 0) return 0;
    return (*(unsigned char *)s1 - *(unsigned char *)--s2);
}

__attribute__((always_inline)) static inline char *my_strstr(const char *s, const char *find) {
    char c, sc;
    size_t len;

    if ((c = *find++) != '\0') {
        len = my_strlen(find);
        do {
            do {
                if ((sc = *s++) == '\0') return NULL;
            } while (sc != c);
        } while (my_strncmp(s, find, len) != 0);
        s--;
    }
    return ((char *)s);
}

static void gen_serial(void) {
  char *charset = "0123456789abcdef";
  int rand_index;
  memset(serialno,0,sizeof serialno); // zero-out the buffer so we don't have to add sentinel to the buffer
  for(int i=0;i<=11;i++) {
    rand_index = rand()%(15+1);
    serialno[i] = charset[rand_index];
  }
}

static void gen_android_id(void) {
  char *charset = "0123456789abcdef";
  int rand_index;
  memset(android_id,0,sizeof android_id); // zero-out the buffer so we don't have to add sentinel to the buffer
  for(int i=0;i<=0xF;i++) {
    rand_index = rand()%(15+1);
    android_id[i] = charset[rand_index];
  }
}

__attribute__((used)) static char *get_android_id(void) {
  return android_id;
}

static void gen_fingerprint(void) {
    char *charset = "0123456789abcdefPQRSABCDJOEUXM";
    int rand_index;
    memset(fingerprint,0,sizeof fingerprint);
    sprintf(fingerprint,
  "%s/%s_%c%c%c/%s:%s/%c%c%d%c.%d.%d/%c%c%c%c%c%c%c:user/release-keys",
  brand,
  product,
  charset[rand()%((14+1-10)+10)],
  charset[rand()%((14+1-10)+10)],
  charset[rand()%((14+1-10)+10)],
  product,
  release,
  (strstr(release,"9"))?charset[0x10]:
  (strstr(release,"10"))?charset[0x11]:
  (strstr(release,"11"))?charset[0x12]:
  charset[0x13],
  charset[rand()%(0x1D+1-0x10)+0x10],
  rand()%(9+1),
  charset[rand()%((0x1D+1-0x14)+0x14)],
  rand()%((200000+1-100000)+100000),
  rand()%((900+1-100)+100),
  (strstr(release,"9"))?charset[0x10]:
  (strstr(release,"10"))?charset[0x11]:
  (strstr(release,"11"))?charset[0x12]:
  charset[0x13],
  charset[rand()%((0x1D+1-0x14)+0x14)],
  charset[rand()%((0x1D+1-0x14)+0x14)],
  charset[rand()%((0x1D+1-0x14)+0x14)],
  charset[rand()%((0x1D+1-0x14)+0x14)],
  charset[rand()%((0x1D+1-0x14)+0x14)],
  charset[rand()%((0x1D+1-0x14)+0x14)]);
}

/*
 * Hook __system_property_get and return false information
 */
static int new_system_property_get(const char *name, char *value) {
#ifdef DEBUG
#ifdef LOGTOFILE
  fprintf(logfile, "__system_property_get(\"%s\")\n", name);
  fflush(logfile);
#else
  __android_log_print(ANDROID_LOG_INFO, THISLIB, "__system_property_get(\"%s\")", name);
#endif
#endif
  srand(time(NULL));
  if(my_strstr(name,"adb") // adb port checks
    ||my_strstr(name,"microvirt") // memu emulator
    ||my_strstr(name,"ldinit") // ldplayer emulator
    ||my_strstr(name,"x86") // common x86 checks
    ||my_strstr(name,"gfx")
    ||my_strstr(name,"qemu")
    ||my_strstr(name,"privapp.list")
    ||my_strstr(name,"debuggable")
    ||my_strstr(name,".pkg")
    ||!my_strcmp(name,"debug.layout")
    ||!my_strcmp(name,"debug.force_rtl")
    ||!my_strcmp(name,"ro.hardware.gps")
    ||!my_strcmp(name,"ro.hardware.sensors")
    ||!my_strcmp(name,"ro.hardware.alter")
    ||!my_strcmp(name,"ro.build.time")
    ||!my_strcmp(name,"ro.simulated.phone")) {
    value[0] = 0;
  } else if(!my_strcmp(name,"ro.hardware")) {
    sprintf(value,"%s",new_hardware);
  } else if(my_strstr(name,"multisim.config")) {
    sprintf(value,"dsds");
  } else if(my_strstr(name,"persist.sys.timezone")) {
    sprintf(value,"Europe/Ljubljana");
  } else if(!my_strcmp(name,"ro.arch")||!my_strcmp(name,"ro.bionic.arch")) {
    sprintf(value,"arm64");
  } else if(!my_strcmp(name,"ro.2nd_arch")||!my_strcmp(name,"ro.bionic.2nd_arch")) {
    sprintf(value,"arm");
  } else if(!my_strcmp(name,"ro.product.cpu.abi")) {
    sprintf(value,"arm64-v8a");
  } else if(!my_strcmp(name,"ro.product.cpu.abilist")) {
    sprintf(value,"arm64-v8a,armeabi-v7a,armeabi");
  } else if(!my_strcmp(name,"ro.product.cpu.abilist32")) {
    sprintf(value,"armeabi-v7a,armeabi");
  } else if(!my_strcmp(name,"ro.product.cpu.abilist64")) {
    sprintf(value,"arm64-v8a");
  } else if(!my_strcmp(name,"ro.product.model")) {
    sprintf(value,"%s Note %d",brand,(rand()%(11-2+1))+2);
#ifndef EMULATED
  } else if(!my_strcmp(name,"ro.board.fingerprint")) { // crashes on real physical arm device
    sprintf(value,"%s",fingerprint);
#endif
  } else if(!my_strcmp(name,"ro.build.version.release")) {
    sprintf(value,"%s",release);
  } else if(!my_strcmp(name,"ro.build.version.sdk")) {
    sprintf(value,"%d",(rand()%(33-25+1))+25);
  } else if(!my_strcmp(name,"gsm.operator.alpha")) {
    sprintf(value,"%s",operator_alpha_table[rand()%OPERATOR_ALPHA_TABLE_SIZE]);
  } else if(!my_strcmp(name,"gsm.operator.numeric")) {
    sprintf(value,"%d",(rand()%(5000-4000+1))+4000);
  } else if(!my_strcmp(name,"gsm.sim.operator.numeric")) {
    sprintf(value,"%d",(rand()%(5000-4000+1))+4000);
#ifndef MOBILE // Necessary to avoid if compiling for real physical arm device
  } else if(!my_strcmp(name,"ro.board.platform")) { // crashes on real physical arm device
    sprintf(value,"%s",new_hardware);
#endif
  } else if(!my_strcmp(name,"ro.product.board")) {
    sprintf(value,"%s",product);
  } else if(!my_strcmp(name,"ro.serialno")) {
    memcpy(value,serialno,13); // copy 13 bytes from serialno to value buffer
  } else {
    return __system_property_get(name,value);
  }
  return my_strlen(value);
}

/*
 * Hook __system_property_find and return false information
 */
static const prop_info *new_system_property_find(const char *name) {
#ifdef DEBUG
#ifdef LOGTOFILE
  fprintf(logfile, "__system_property_find(\"%s\")\n", name);
  fflush(logfile);
#else
  __android_log_print(ANDROID_LOG_INFO, THISLIB, "__system_property_find(\"%s\")", name);
#endif
#endif
  return __system_property_find("brrrrrr");
}

/*
 * Hook open and return failure for restricted file
 */
static int new_open(const char *path, int flags) { //new_openat(int dirfd, const char *path, int flags, int mode) {
#ifdef DEBUG
#ifdef LOGTOFILE
  fprintf(logfile, "openat(\"%s\", %#x)\n", path, flags);
  fflush(logfile);
#else
  __android_log_print(ANDROID_LOG_INFO, THISLIB, "open(\"%s\", %#x)", path, flags);
#endif
#endif
  const char *fname, *ext;
  fname = basename(path);
  ext = (strchr(fname,'.'))?strchr(fname,'.')+1:NULL;

  if(!my_strcmp(fname,"maps")
    ||!my_strcmp(fname,"smaps")
    ||!my_strcmp(fname,"hosts")
    ||!my_strcmp(fname,"cmdline")
    ||!my_strcmp(ext,"log")
    ||!my_strcmp(ext,"zip")
    ||!my_strcmp(ext,"tmp")
    //||!my_strstr(path,"framework")
    ) {
    return open("/dev/null",flags); //openat(dirfd, "/dev/null", flags, mode);
#ifndef EMULATED
  } else if(!my_strcmp(fname,"cpuinfo")) {
    return open("/data/data/com.snapchat.android/.cpuinfo",flags) ; //openat(dirfd, "/data/data/com.snapchat.android/.cpuinfo", flags, mode);
#endif
  } else {
    return open(path,flags); //openat(dirfd, path, flags, mode);
  }
}

static int new_execve(const char* file, char* const* argv, char* const* envp) {
  return execve("/blah",NULL,envp);
}

int print_sym(const GumSymbolDetails * details, gpointer user_data) {
  __android_log_print(ANDROID_LOG_INFO, "/system/lib64/arm64/nb/libc.so", " symbol name: %s, address: %#lx", details->name, details->address);
  if(!my_strcmp(details->name,"__openat")) {
#ifdef DEBUG
    __android_log_print(ANDROID_LOG_INFO, "/system/lib64/arm64/nb/libc.so", " symbol name: %s, address: %#lx", details->name, details->address);
#endif
    openataddr = details->address;
  }
  return 1;
}

char* DumpHex2(const void* data, size_t size) {
    const int symbolSize = 100;
    char* buffer = calloc(10*size, sizeof(char));
    char* symbol = calloc(symbolSize, sizeof(char));

    char ascii[17];
    size_t i, j;
    ascii[16] = '\0';
    for (i = 0; i < size; ++i) {
        snprintf(symbol, symbolSize, "%02X ", ((unsigned char*)data)[i]);
        strcat(buffer, symbol);
        memset(symbol,0,strlen(symbol));
        if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
            ascii[i % 16] = ((unsigned char*)data)[i];
        } else {
            ascii[i % 16] = '.';
        }
        if ((i+1) % 8 == 0 || i+1 == size) {
            strcat(buffer, " ");
            if ((i+1) % 16 == 0) {
                snprintf(symbol, symbolSize, "|  %s \n", ascii);
                strcat(buffer, symbol);
                memset(symbol,0,strlen(symbol));
            } else if (i+1 == size) {
                ascii[(i+1) % 16] = '\0';
                if ((i+1) % 16 <= 8) {
                    strcat(buffer, " ");
                }
                for (j = (i+1) % 16; j < 16; ++j) {
                    strcat(buffer, "   ");
                }
                snprintf(symbol, symbolSize, "|  %s \n", ascii);
                strcat(buffer, symbol);
                memset(symbol,0,strlen(symbol));
            }
        }
    }

    free(symbol);

    return buffer;
}

int matched_bytes(GumAddress address, gsize size, gpointer user_data) {
  //static int svc_count = 0x0;
  //++svc_count;
  guint8 patch[4] = {0x00,0x00,0x80,0x92};
  gum_mprotect(GSIZE_TO_POINTER(address+4),4,GUM_PAGE_RW); // address+4
  gum_memory_write(GSIZE_TO_POINTER(address+4),patch,sizeof(patch)); // address+4
  gum_mprotect(GSIZE_TO_POINTER(address+4),4,GUM_PAGE_RX); // address+4
  //__android_log_print(ANDROID_LOG_INFO, "libc.so", "bytes matched at %lx, count=%d, after = { %s }",address,svc_count,DumpHex2(address,8));
  return 1;
}

int enum_range(const GumRangeDetails * details, gpointer user_data) {
  __android_log_print(ANDROID_LOG_INFO, "libc.so", "inside enum_range");
  GumMatchPattern * pattern;
  GumMemoryScanMatchFunc matchfn = &matched_bytes;
  pattern = gum_match_pattern_new_from_string("E8 09 80 D2 01 00 00 D4");
  gum_memory_scan(details->range,pattern,matchfn,NULL);
  pattern = gum_match_pattern_new_from_string("08 07 80 D2 01 00 00 D4");
  gum_memory_scan(details->range,pattern,matchfn,NULL);
  return 1;
}

static void example_listener_on_enter (GumInvocationListener * listener, GumInvocationContext * ic) {
  ExampleListener * self = EXAMPLE_LISTENER (listener);
  ExampleHookId hook_id = GUM_IC_GET_FUNC_DATA (ic, ExampleHookId);
  GumFoundRangeFunc rfn = &enum_range;
  const char *hook_lib = "libscplugin.so";
  switch (hook_id)
  {
    case HOOK_CALL_ARRAY:
    gum_module_enumerate_ranges("libscplugin.so",GUM_PAGE_X,enum_range,NULL);
    //__android_log_print(ANDROID_LOG_INFO,"linker64","loading lib: %s", (const char *) gum_invocation_context_get_nth_argument (ic, 3));
    break;
  }
}

static void example_listener_on_leave (GumInvocationListener * listener, GumInvocationContext * ic) {
}

static void example_listener_class_init (ExampleListenerClass * klass) {
  (void) EXAMPLE_IS_LISTENER;
  (void) glib_autoptr_cleanup_ExampleListener;
}

static void example_listener_iface_init (gpointer g_iface, gpointer iface_data) {
  GumInvocationListenerInterface * iface = g_iface;

  iface->on_enter = example_listener_on_enter;
  iface->on_leave = example_listener_on_leave;
}

static void example_listener_init (ExampleListener * self) {
}

__attribute__((constructor)) int main(void) {
 GumInterceptor *interceptor;
#ifndef EMULATED
 float bmips;
 int cpu_imp;
 int cpu_var;
 int cpu_par;
 int cpu_rev;
 char tmp[6];
#endif
#ifdef DEBUG
  __android_log_print(ANDROID_LOG_INFO, THISLIB, "entrypoint");
  system("rm -rf /data/data/com.snapchat.android/.cpuinfo"); // remove cpuinfo file
#ifdef LOGTOFILE
#ifdef X86
  logfile = fopen("/data/data/com.snapchat.android/libsnap2half_x86.log","w");
#elif defined X64
  logfile = fopen("/data/data/com.snapchat.android/libsnap2half_x64.log","w");
#elif defined ARM
  logfile = fopen("/data/data/com.snapchat.android/libsnap2half_arm.log","w");
#else
  logfile = fopen("/data/data/com.snapchat.android/libsnap2half_arm64.log","w");
#endif
#endif
#endif
  srand(time(NULL));
  brand = brand_table[rand()%BRAND_TABLE_SIZE];
  product = product_table[rand()%PRODUCT_TABLE_SIZE];
  release = release_table[rand()%RELEASE_TABLE_SIZE];
  new_hardware = hardware_table1[rand()%HARDWARE1_TABLE_SIZE];
  gen_serial();
  gen_android_id();
#ifndef EMULATED
  gen_fingerprint();
  sprintf(tmp,"%d.%d",(rand()%(40-26+1))+26,(rand()%(5-1+1))+1);
  bmips = atof(tmp);
  bmips = floorf(bmips*100)/100;
  cpu_imp = (16*((rand()%(5-2+1))+2))+1;
  cpu_var = (rand()%(0xA-0x1+1))+0xA;
  cpu_par = (rand()%(4000-2000+1))+2000;
  cpu_rev = (rand()%(5-0+1))+5;

#ifndef MOBILE
  FILE* cpuinfoptr = fopen("/data/data/com.snapchat.android/.cpuinfo","w");
  if (cpuinfoptr != NULL) {
    for(int i=0; i!=8; i++) {
      fprintf(cpuinfoptr,
        "processor       : %d\n"
        "BogoMIPS        : %f\n"
        "Features        : fp asimd evtstrm aes pmull sha1 sha2 crc32\n"
        "CPU implementer : %#x\n"
        "CPU architecture: 8\n"
        "CPU variant     : %#x\n"
        "CPU part        : %#x\n"
        "CPU revision    : %d\n\n",
        i,
        bmips,
        cpu_imp,
        cpu_var,
        cpu_par,
        cpu_rev);
      if(i == 7) fprintf(cpuinfoptr,"Hardware        : %s\n",hardware_table[rand()%HARDWARE_TABLE_SIZE]);
      fflush(cpuinfoptr);
    }
    fclose(cpuinfoptr);
  }
#endif
#endif
  gum_init_embedded();
  interceptor = gum_interceptor_obtain();
  gum_interceptor_begin_transaction(interceptor);

#if defined EMULATED && ARM64
  gum_interceptor_replace(interceptor,(gpointer) gum_module_find_export_by_name("/system/lib64/arm64/nb/libc.so", "open"), new_open, NULL);
  gum_interceptor_replace(interceptor,(gpointer) gum_module_find_export_by_name("/system/lib64/arm64/nb/libc.so", "__system_property_find"), new_system_property_find, NULL);
  gum_interceptor_replace(interceptor,(gpointer) gum_module_find_export_by_name("/system/lib64/arm64/nb/libc.so", "__system_property_get"), new_system_property_get, NULL);
  gum_interceptor_replace(interceptor,(gpointer)gum_module_find_export_by_name("/system/lib64/arm64/nb/libc.so", "execve"), new_execve, NULL);
#elif defined EMULATED && ARM
  gum_interceptor_replace(interceptor,(gpointer) gum_module_find_export_by_name("/system/lib/arm/nb/libc.so", "open"), new_open, NULL);
  gum_interceptor_replace(interceptor,(gpointer) gum_module_find_export_by_name("/system/lib/arm/nb/libc.so", "__system_property_find"), new_system_property_find, NULL);
  gum_interceptor_replace(interceptor,(gpointer) gum_module_find_export_by_name("/system/lib/arm/nb/libc.so", "__system_property_get"), new_system_property_get, NULL);
  gum_interceptor_replace(interceptor,(gpointer)gum_module_find_export_by_name("/system/lib/arm/nb/libc.so", "execve"), new_execve, NULL);
#else
  gum_interceptor_replace(interceptor,(gpointer) gum_module_find_export_by_name(NULL, "open"), new_open, NULL);
  gum_interceptor_replace(interceptor,(gpointer) gum_module_find_export_by_name(NULL, "__system_property_find"), new_system_property_find, NULL);
  gum_interceptor_replace(interceptor,(gpointer) gum_module_find_export_by_name(NULL, "__system_property_get"), new_system_property_get, NULL);
  gum_interceptor_replace(interceptor,(gpointer)gum_module_find_export_by_name(NULL, "execve"), new_execve, NULL);
#endif
  gum_interceptor_end_transaction(interceptor);
  return EXIT_SUCCESS;
}
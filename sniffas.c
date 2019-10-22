/*
 * This is free and unencumbered software released into the public domain.
 * see the attached UNLICENSE or http://unlicense.org/
 */

#include <android/log.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <sys/sysconf.h>
#include <stdlib.h>
#include <string.h>

#define log(x) __android_log_write(ANDROID_LOG_DEBUG, __FILE__, x);

#define java_func(func) \
    Java_com_klab_nativeinput_NativeInputJava_##func

#define exports(macro) \
  macro(java_func(clearTouch)) \
  macro(java_func(lock)) \
  macro(java_func(onFinalize)) \
  macro(java_func(stockDeviceButtons)) \
  macro(java_func(stockNativeTouch)) \
  macro(java_func(testOverrideFlgs)) \
  macro(java_func(unlock)) \

/*
  I decided to go with absolute jmp's. since arm doesn't allow 32-bit
  immediate jumps I have to place the address right after the jmp and
  reference it using [pc,#-4]. pc is 8 bytes after the current instruction,
  so #-4 reads 4 bytes after the current instruction.
  0xBAADF00D is then replaced by the correct address at runtime
*/

#define define_trampoline(name) \
void __attribute__((naked)) name() { \
    asm("ldr pc,[pc,#-4]"); \
    asm(".word 0xBAADF00D"); \
}

/* runs define_trampoline on all functions listed in exports */
exports(define_trampoline)

#define stringify_(x) #x
#define stringify(x) stringify_(x)
#define to_string_array(x) stringify(x),
static char* export_names[] = { exports(to_string_array) 0 };

void (*_onInitialize)(void* env);

/*
  make memory readadable, writable and executable. size is
  ceiled to a multiple of PAGESIZE and addr is aligned to
  PAGESIZE
*/
#define PROT_RWX (PROT_READ | PROT_WRITE | PROT_EXEC)
#define PAGESIZE sysconf(_SC_PAGESIZE)
#define PAGEOF(addr) (void*)((int)(addr) & ~(PAGESIZE - 1))
#define PAGE_ROUND_UP(x) \
    ((((int)(x)) + PAGESIZE - 1) & (~(PAGESIZE - 1)))
#define munprotect(addr, n) \
    mprotect(PAGEOF(addr), PAGE_ROUND_UP(n), PROT_RWX)

typedef struct {
  char unknown[8];
  int Length;
  unsigned short Data[1];
} String;

/* truncate to ascii. good enough for now */
static
void String_log(String* str) {
  int i;
  char* buf = malloc(str->Length + 1);
  for (i = 0; i < str->Length; ++i) {
    buf[i] = (char)str->Data[i];
  }
  buf[str->Length] = 0;
  log(buf);
  free(buf);
}

typedef struct {
  char unknown[12];
  int Length;
  char Data[1];
} Array;

static
void Array_log_ascii(Array* arr) {
  char* buf;
  if (!arr) {
    log("(null array)");
    return;
  }
  buf = malloc(arr->Length + 1);
  if (!buf) {
    log("(empty array or OOM)");
    return;
  }
  memcpy(buf, arr->Data, arr->Length);
  buf[arr->Length] = 0;
  log(buf);
  free(buf);
}

typedef struct {
  char unknown[8];
  int Status;
  Array* Bytes;
  char isTimeout;
  char isNetworkError;
  String* ErrorMessage;
} Response;

static
void (*original_PostJson)(String* url, Array* body, void* delegate,
  void* unk);

static
void hooked_PostJson(String* url, Array* body, void* delegate, void* unk) {
  String_log(url);
  Array_log_ascii(body);
  original_PostJson(url, body, delegate, unk);
}

static
Array* (*original_get_Bytes)(Response* resp);

static
Array* hooked_get_Bytes(Response* resp) {
  Array_log_ascii(resp->Bytes);
  return original_get_Bytes(resp);
}

typedef struct {
  char unk[16];
  char* end;
  char* start;
} std_string;

typedef struct {
  char* data;
  int length;
} hash_array;

/* unused */
static hash_array* (*original_hash)(hash_array* pphash, std_string* path,
  int type);

hash_array* (*md5)(hash_array* hash, std_string* path);
hash_array* (*sha1)(hash_array* hash, std_string* path);
hash_array* (*sha256)(hash_array* hash, std_string* path);

static
__attribute__((target("thumb")))
hash_array* hooked_hash(hash_array* hash, std_string* path, int type) {
  hash_array* res;
  char buf[1024];
  char* p = buf;
  int i;
  p += sprintf(p, "hash called with type %d on ", type);
  memcpy(p, path->start, path->end - path->start);
  p[path->end - path->start] = 0;
  log(buf);
  switch (type) {
    case 0: res = md5(hash, path); break;
    case 1: res = sha1(hash, path); break;
    case 2: res = sha256(hash, path); break;
    default:
      log("unknown hash!");
      hash->data = 0;
      hash->length = 0;
      return hash;
  }
  p = buf;
  p += sprintf(p, "result: ");
  for (i = 0; i < res->length; ++i) {
    p += sprintf(p, "%02x", hash->data[i]);
  }
  log(buf);
  return res;
}

#define THUMB (1<<1)

static
void hook(char* name, char* addr, void** ptrampoline, void* dst, int fl) {
  char buf[512];
  int i;
  char *p;
  unsigned* code;

  unsigned absolute_jump =
    (fl & THUMB) ?
      0xF000F8DF:  /* thumb mode: ldr pc,[pc]     */
      0xE51FF004;  /*   arm mode: ldr pc,[pc,#-4] */

  p = buf;
  p += sprintf(p, "%s at %p: ", name, addr);
  for (i = 0; i < 8; ++i) {
    p += sprintf(p, "%02x ", addr[i]);
  }
  log(buf);
  sprintf(buf, "-> %p", dst);
  log(buf);

  /*
   * alloc a trampoline to call the original function.
   * it's a copy of the instructions we overwrote followed by a jmp to
   * right after where hook jump will be in the original function
   * again using an abosolute jump like in the asm trampolines
   */
  *ptrampoline = malloc(8 + 8);
  code = (unsigned*)*ptrampoline;
  munprotect(code, 8 + 8);
  memcpy(code, addr, 8);
  code[2] = absolute_jump;
  code[3] = (unsigned)addr + 8;

  /*
   * overwrite the original function's first 8 bytes with an absolute jump
   * to our hook
   */
  code = (unsigned*)addr;
  munprotect(code, 8);
  code[0] = absolute_jump;
  code[1] = (unsigned)dst;
}

static
void init() {
  char** s;
  void *original, *stub, *il2cpp, *known_export, *jackpot;
  Dl_info dli;
  char buf[512];

  log("hello from the stub library!");
  original = dlopen("libKLab.NativeInput.Native.so.bak", RTLD_LAZY);
  stub = dlopen("libKLab.NativeInput.Native.so", RTLD_LAZY);
  for (s = export_names; *s; ++s) {
    void** stub_func = dlsym(stub, *s);
    log(*s);
    munprotect(&stub_func[1], sizeof(void*));
    stub_func[1] = dlsym(original, *s);
  }
  *(void**)&_onInitialize =
    dlsym(original, stringify(java_func(onInitialize)));

  /* libil2cpp.so */
  /* get base address through a known export */
  il2cpp = dlopen("libil2cpp.so", RTLD_LAZY);
  known_export = dlsym(il2cpp, "UnityAdsEngineInitialize");
  dladdr(known_export, &dli);
  sprintf(buf, "il2cpp at %p", dli.dli_fbase);
  log(buf);

#define h(name, addr) \
  hook(#name, (char*)dli.dli_fbase + addr, (void**)&original_##name, \
    hooked_##name, 0)

  h(PostJson, 0x8ff004);
  h(get_Bytes, 0x8ffaf0);

#undef h

  /* libjackpot-core.so */
  jackpot = dlopen("libjackpot-core.so", RTLD_LAZY);
  known_export = dlsym(jackpot, "_KJACore_AssetStateLogGenerateV2");
  dladdr(known_export, &dli);
  sprintf(buf, "jackpot-core at %p", dli.dli_fbase);
  log(buf);

#define h(name, addr, fl) \
  hook(#name, (char*)dli.dli_fbase + addr, (void**)&original_##name, \
    hooked_##name, fl)

  h(hash, 0x133dc, THUMB);

#undef h

  /* | 1 forces thumb mode */
#define f(name, addr) \
  *(int*)&name = ((int)dli.dli_fbase + addr) | 1

  f(md5, 0x13218);
  f(sha1, 0x132ac);
  f(sha256, 0x13344);

#undef f
}

void java_func(onInitialize)(void* env) {
  init();
  _onInitialize(env);
}

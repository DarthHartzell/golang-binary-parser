#include <inttypes.h>
#include <elf.h>

typedef struct sections
{
    char name[64];
    Elf64_Shdr section_header;
} ElfSections, *pElfSections;

typedef enum
{
    Invalid_Kind,
    Bool,
    Int,
    Int8,
    Int16,
    Int32,
    Int64,
    Uint,
    Uint8,
    Uint16,
    Uint32,
    Uint64,
    Uintptr,
    Float32,
    Float64,
    Complex64,
    Complex128,
    Array,
    Chan,
    Func,
    Interface,
    Map,
    Ptr,
    Slice,
    String,
    Struct,
    UnsafePointer
} Kinds;

typedef struct 
{
    uint64_t size;          // 0
    uint64_t ptrdata;       // 8
    uint32_t hash;          // 16
    uint8_t tflag;          // 20
    uint8_t align;          // 21
    uint8_t field_align;    // 22
    uint8_t kind:5;         // 23
    uint8_t kind_trash:3;   // 23
    uint64_t alg;           // 24
    uint64_t gcdata;        // 32
    uint32_t name_off;      // 40
    uint32_t ptrtothis_off; // 36
    // extra fields begin at offset 48, fields depend on 'Kind'
    char name[256];
} __attribute__((packed, aligned(1))) RType, *pRType;

typedef struct
{
    uint64_t pclntable;
    uint64_t pclntable_len;
    uint64_t pclntable_cap;
    uint64_t ftab;
    uint64_t ftab_len;
    uint64_t ftab_cap;
    uint64_t filetab;
    uint64_t filetab_len;
    uint64_t filetab_cap;
    uint64_t findfunctab;
    uint64_t minpc;
    uint64_t maxpc;
    uint64_t text;
    uint64_t etext;
    uint64_t noptrdata;
    uint64_t enoptrdata;
    uint64_t data;
    uint64_t edata;
    uint64_t bss;
    uint64_t ebss;
    uint64_t noptrbss;
    uint64_t enoptrbss;
    uint64_t end;
    uint64_t gcdata;
    uint64_t gcbss;
    uint64_t types;
    uint64_t etypes;
    uint64_t textsectmap;
    uint64_t textsectmap_len;
    uint64_t textsectmap_cap;
    uint64_t typelinks;
    uint64_t typelinks_len;
    uint64_t typelinks_cap;
    uint64_t itablinks;
    uint64_t itablinks_len;
    uint64_t itablinks_cap;
    uint64_t ptab;
    uint64_t ptab_len;
    uint64_t pluginpath;
    uint64_t pkghashes;
    uint64_t pkghashes_len;
    uint64_t pkghashes_cap;
    uint64_t modulename;
    uint64_t modulehashes;
    uint64_t modulehashes_len;
    uint64_t modulehashes_cap;
    uint8_t hasmain;
    uint64_t gcdatamask;
    uint64_t gcbssmask;
    uint64_t typemap;
    uint8_t bad;
    uint64_t next;
} ModuleData, *pModuleData;

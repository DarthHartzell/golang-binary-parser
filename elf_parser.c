
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <regex.h>
#include "elf_parser.h"
#include <elf.h>
#include <capstone/capstone.h>


static pElfSections g_sections = NULL;
static uint16_t g_num_sections = 0;
pModuleData g_pmd = NULL;

char **g_static_strings = NULL;
int g_num_static_strings = 0;
int g_max_static_strings = 0;

char **g_dynamic_strings = NULL;
int g_num_dynamic_strings = 0;
int g_max_dynamic_strings = 0;

char **g_file_tab = NULL;
int g_num_file_tab = 0;
int g_max_file_tab = 0;

char **g_func_tab = NULL;
int g_num_func_tab = 0;
int g_max_func_tab = 0;

char **g_symtab_symbols = NULL;
int g_num_symtab_symbols = 0;
int g_max_symtab_symbols = 0;

uint64_t g_va_offset = 0;

int section_compare( void const *lhs, void const *rhs )
{
    pElfSections ls = (pElfSections)lhs;
    pElfSections rs = (pElfSections)rhs;
    return strcmp( ls->name, rs->name );
}

const uint8_t elf_magic[] = {0x7f, 0x45, 0x4c, 0x46};

void read_section_header( const char* elfFile, uint64_t shoff,
                          uint16_t sh_ent_size, uint16_t sh_num,
                          uint16_t sh_st_idx)
{
    Elf64_Shdr *sh_header;
    Elf64_Shdr *strtab;
    int i;

    g_sections = calloc( sh_num, sizeof(ElfSections));
    g_num_sections = sh_num;

    sh_header = (Elf64_Shdr*) &elfFile[shoff];
    strtab = (Elf64_Shdr*) &sh_header[sh_st_idx];
    const char *const sh_strtab_p = elfFile + strtab->sh_offset;
    for( i = 0; i < sh_num; ++i )
    {
        if( sh_header[i].sh_name )
        {
            const char *sec_name = sh_strtab_p + sh_header[i].sh_name;
            strcpy(g_sections[i].name, sec_name);
        }
        memcpy(&g_sections[i].section_header, &sh_header[i], sizeof(Elf64_Shdr));
    }
    qsort( g_sections, g_num_sections, sizeof(ElfSections), section_compare );
}

ElfSections * getSectionByName( const char * name )
{
    ElfSections es = {0};
    pElfSections pes;
    strcpy(es.name, name);
    pes = bsearch( &es, g_sections, g_num_sections, sizeof(ElfSections), section_compare );
    return pes;
}

void read_elf_header( const char* elfFile )
{
    Elf64_Ehdr *header = (Elf64_Ehdr *)&elfFile[0];
    if( !memcmp(elf_magic, elfFile, sizeof(elf_magic)) )
    {
        printf("memcmp elf magic number returned match\n");
    }
    else
    {
        exit(1);
    }

    printf("type=%x\n", header->e_type);
    printf("machine=%x\n", header->e_machine);
    printf("version=%x\n", header->e_version);
    printf("entry point virtual address=0x%lx\n", header->e_entry);
    printf("program header table file offset: 0x%lx\n", header->e_phoff);
    printf("section header table file offset: 0x%lx\n", header->e_shoff);
    printf("processor specific flags: %x\n", header->e_flags);
    printf("elf header size in bytes 0x%x\n", header->e_ehsize);
    printf("program header table entry size in bytes 0x%x\n", header->e_phentsize);
    printf("program header table entry count %d\n", header->e_phnum );
    printf("section header table entry size in bytes 0x%x\n", header->e_shentsize );
    printf("section header table entry count %d\n", header->e_shnum );
    printf("section header string table index %d\n\n", header->e_shstrndx );
    read_section_header( elfFile,  header->e_shoff,
                         header->e_shentsize, header->e_shnum,
                        header->e_shstrndx);
}

void parse_func_tab( const char * buffer )
{
    int i;
    uint64_t entry_offset;
    uint32_t func_name_offset;
    uint64_t str_offset;

    const char *temp_string;
    pElfSections pGoPcLnTab = getSectionByName(".gopclntab");
    uint64_t base = pGoPcLnTab->section_header.sh_offset;
    uint64_t addr = base + 8;

    uint64_t size = *(uint64_t*)&buffer[addr];
    uint64_t offset;

    g_max_func_tab = 256;
    g_func_tab = calloc( sizeof(char*), g_max_func_tab );

    for( i = 1; i < size*2; i += 2 )
    {
        offset = addr + (i*8);
        entry_offset = *(uint64_t*)&buffer[offset+8];
        func_name_offset = *(uint32_t*)&buffer[entry_offset+base+8];
        str_offset = func_name_offset + base;

        temp_string = &buffer[str_offset];
        // printf("found one: %s\n", temp_string);

        g_func_tab[g_num_func_tab] = calloc( strlen(temp_string) + 1, 1 );
        strcpy( g_func_tab[g_num_func_tab], temp_string );
        ++g_num_func_tab;
        if( g_num_func_tab + 1 >= g_max_func_tab )
        {
            g_max_func_tab *= 2;
            g_func_tab = realloc(g_func_tab, g_max_func_tab*sizeof(char*));
        }
        // printf("parsing file tab\n");
    }
    printf("found %d func tab\n", g_num_func_tab);
}

void parse_file_tab( const char * buffer )
{
    int i;
    uint64_t offset;
    uint64_t file_tab_offset;
    uint64_t file_tab_str_offset;
    uint32_t index;
    const char *temp_string;

    g_max_file_tab = 256;
    g_file_tab = calloc( sizeof(char*), g_max_file_tab );

    for( i = 1; i < g_pmd->filetab_len; ++i )
    {
        offset = g_pmd->filetab + (i*4);
        file_tab_offset = offset - g_va_offset;
        index = *(uint32_t*)&buffer[file_tab_offset];
        file_tab_str_offset = index + g_pmd->pclntable - g_va_offset;
        temp_string = &buffer[file_tab_str_offset];
        g_file_tab[g_num_file_tab] = calloc( strlen(temp_string) + 1, 1 );
        strcpy( g_file_tab[g_num_file_tab], temp_string );
        ++g_num_file_tab;
        if( g_num_file_tab + 1 >= g_max_file_tab )
        {
            g_max_file_tab *= 2;
            g_file_tab = realloc(g_file_tab, g_max_file_tab*sizeof(char*));
        }
        // printf("parsing file tab\n");
    }
    printf("found %d file tab\n", g_num_file_tab);
}

void parse_itab_symbols( const char * buffer )
{
    uint32_t i;
    pElfSections pStrTab = getSectionByName(".strtab");
    pElfSections pSymTab = getSectionByName(".symtab");

    uint64_t end_symbols = (pSymTab->section_header.sh_size / 
                            pSymTab->section_header.sh_entsize) * 0x18;
    uint64_t start_sym_tab = pSymTab->section_header.sh_offset;
    const Elf64_Sym * sym_data;
    const char* temp_str;
    uint64_t start_strtab = pStrTab->section_header.sh_offset;
    printf("end=%ld\n", end_symbols);

    g_max_symtab_symbols = 256;
    g_symtab_symbols = calloc( sizeof(char*), g_max_symtab_symbols );

    for( i = 0; i < end_symbols; i += 0x18 )
    {
        sym_data = (const Elf64_Sym *)&buffer[start_sym_tab+i];
        temp_str = (const char*)&buffer[start_strtab+sym_data->st_name];
        // printf("temp_str=%s\n", temp_str);
        g_symtab_symbols[g_num_symtab_symbols] = calloc( strlen(temp_str) + 1, 1 );
        strcpy( g_symtab_symbols[g_num_symtab_symbols], temp_str );
        ++g_num_symtab_symbols;
        if( g_num_symtab_symbols + 1 >= g_max_symtab_symbols )
        {
            g_max_symtab_symbols *= 2;
            g_symtab_symbols = realloc( g_symtab_symbols, g_max_symtab_symbols*sizeof(char*) );
        }
    }
    printf("found %d symbols\n", g_num_symtab_symbols);
}

pElfSections get_section_by_va( uint64_t addr )
{
    int i;
    for( i = 0; i < g_num_sections; ++i )
    {
        if( g_sections[i].section_header.sh_addr <= addr && 
            addr < g_sections[i].section_header.sh_addr + g_sections[i].section_header.sh_size)
            {
                return &g_sections[i];
            }
    }
    return NULL;
}

void parse_structs( const char * buffer )
{
    // pElfSections tbaseSection;
    // pElfSections baseSection;
    int i;
    pRType prt;
    uint32_t type_offset;
    // uint32_t type_addr;
    uint64_t types = g_pmd->types;
    uint64_t typeslinkaddr = g_pmd->typelinks;
    uint64_t typeslinkLen = g_pmd->typelinks_len;
    // const char *tbase = (const char*)&buffer[types];
    // const char *base = (const char*)&buffer[typeslinkaddr];
    pElfSections type_link_data = get_section_by_va( typeslinkaddr );
    uint64_t start_type_link_data = type_link_data->section_header.sh_offset;
    pElfSections ro_data = get_section_by_va( types );
    uint64_t start_ro_data = ro_data->section_header.sh_offset;
    uint16_t name_len;
    uint64_t offset;

    for( i = 0; i < typeslinkLen; i += 4 )
    {
        type_offset = *(uint32_t*)&buffer[start_type_link_data+i];
        prt = (pRType)&buffer[ start_ro_data+type_offset ];
        offset = start_ro_data + prt->name_off;
        name_len = (buffer[ offset + 1 ])<<8 | (buffer[ offset + 2 ]);
        memcpy( prt->name, &buffer[ start_ro_data + prt->name_off + 3 ], name_len );
        printf("%d\n", prt->kind);
    }
    printf("woot\n");
}

int check_string( char * str, int len )
{
    int i;
    for( i = 0; i < len; ++i )
    {
        if( str[i] < 0x20 || str[i] > 0x7e )
        {
            return 0;
        }
    }
    return 1;
}

void parse_dynamic_strings( const char * buffer )
{
    csh handle;
    cs_insn *insn;
    cs_insn saved_instructions[2] = {0};
    int64_t i, ret, count;
    int64_t str_ptr = 0;
    regex_t expression = {0};
    pElfSections pTextSec = getSectionByName(".text");
    pElfSections pRoData = getSectionByName(".rodata");
    regmatch_t match = {0};
    uint64_t text_end;
    uint64_t ro_start = pRoData->section_header.sh_addr;
    uint64_t ro_end = ro_start + pRoData->section_header.sh_size;

    ret = cs_open( CS_ARCH_X86, CS_MODE_64, &handle );
    if( ret != CS_ERR_OK )
    {
        return;
    }

    g_max_dynamic_strings = 256;
    g_dynamic_strings = calloc( sizeof(char*), g_max_static_strings );

    ret = regcomp( &expression, "0x[0-9a-f]+", REG_EXTENDED );
    text_end = pTextSec->section_header.sh_addr + pTextSec->section_header.sh_size;
    
    // turn on SKIPDATA mode
    cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);

    count = cs_disasm( handle, 
                       (const uint8_t *)&buffer[pTextSec->section_header.sh_offset],
                       pTextSec->section_header.sh_size,
                       pTextSec->section_header.sh_addr,
                       0, &insn );
    for( i = 0; i < count; ++i )
    {
        uint8_t bad = 0;
        // if( insn[i].address > 4205820 )
        // printf("bling\n");
        if( strcmp( "lea", insn[i].mnemonic ) && strcmp( "mov", insn[i].mnemonic ) )
        {
            continue;
        }
        if( saved_instructions[0].id == 0 )
        {
            if( strcmp( "lea", insn[i].mnemonic ) == 0 )
            {
                char my_op_str[160] = {0};
                char *op = strchr( insn[i].op_str, ',' );
                if( NULL != op )
                {

                    ret = regexec( &expression, op, 1, &match, 0 );
                    if( ret != REG_NOMATCH && NULL != op )
                    {
                        // op = op += match.rm_so;
                        op[match.rm_eo] = '\0';
                        strcpy(my_op_str, &op[match.rm_so]);
                        str_ptr = insn[i].address + strtol(my_op_str, NULL, 16);
                        if( str_ptr < text_end )
                        {
                            continue;
                        }
                        memcpy( &saved_instructions[0], &insn[i], sizeof(cs_insn) );
                    }
                }
            }
        }
        else if( saved_instructions[1].id == 0 )
        {
            if( 0 == strcmp( "mov", insn[i].mnemonic ) )
            {
                char *op = strchr( insn[i].op_str, ',' );
                if( NULL != op )
                {
                    char * op0 = strtok( insn[i].op_str, "," );
                    char * op1 = strtok( NULL, "," );

                    if( NULL == strstr( op0, "rsp" ) ||
                        NULL == strstr( op1, "rax" ) )
                    {
                        bad = 1;
                    }
                    else
                    {
                        memcpy( &saved_instructions[1], &insn[i], sizeof(cs_insn) );
                    }
                }
                else
                {
                    bad = 1;
                }
            }
            else
            {
                bad = 1;
            }
        }
        else
        {
            if( 0 == strcmp( "mov", insn[i].mnemonic ) )
            {
                char *op = strchr( insn[i].op_str, ',' );
                if( NULL != op )
                {
                    ret = regexec( &expression, op, 1, &match, 0 );
                    if( ret != REG_NOMATCH )
                    {
                        char my_op_str[160];
                        op[match.rm_eo] = '\0';
                        strcpy( my_op_str, &op[match.rm_so] );
                        uint64_t str_len = strtol( my_op_str, NULL, 16 );
                        if( ro_start < str_ptr && str_ptr < ro_end )
                        {
                            if( str_len < 256 && str_len > 0 )
                            {
                                char s[256] = {0};
                                memcpy(s, &buffer[str_ptr - g_va_offset], str_len);
                                if( check_string( s, str_len ) )
                                {
                                    g_dynamic_strings[g_num_dynamic_strings] = calloc( str_len+1, 1 );
                                    memcpy(g_dynamic_strings[g_num_dynamic_strings], s, str_len);
                                    ++g_num_dynamic_strings;
                                    if( g_num_dynamic_strings + 1 >= g_max_dynamic_strings )
                                    {
                                        g_max_dynamic_strings *= 2;
                                        g_dynamic_strings = realloc(g_dynamic_strings, g_max_dynamic_strings*sizeof(char*));
                                    }
                                }
                            }
                        }
                    }
                }
                bad = 1;
            }
            else
            {
                bad = 1;
            }
        }
        if( bad )
        {
            memset( &saved_instructions[0], 0, sizeof(saved_instructions) );
            str_ptr = 0;
        }
    }
    regfree(&expression);
    cs_free( insn, count );
    cs_close( &handle );
}

void parse_static_strings( const char * buffer )
{
    int i;
    uint64_t data_end, rodata_start, rodata_end;
    uint64_t addr;
    uint64_t str_len;
    char *str;
    pElfSections pDataSec = getSectionByName(".data");
    pElfSections pRoDataSec = getSectionByName(".rodata");

    g_max_static_strings = 256;
    g_static_strings = calloc( sizeof(char*), g_max_static_strings );

    g_va_offset = pRoDataSec->section_header.sh_addr - pRoDataSec->section_header.sh_offset;
    i = pDataSec->section_header.sh_offset;
    data_end = pDataSec->section_header.sh_offset + pDataSec->section_header.sh_size;
    rodata_start = pRoDataSec->section_header.sh_addr;
    rodata_end = pRoDataSec->section_header.sh_addr + pRoDataSec->section_header.sh_size;
    for( ; i < data_end; i += 16 )
    {
        addr = *(uint64_t*)&buffer[i];
        if( rodata_start < addr && addr < rodata_end )
        {
            // printf("first addr\n");
            str_len = *(uint64_t*)&buffer[i+8];
            if( 256 > str_len && 0 < str_len )
            {
                // printf("strlen=%ld\n", str_len);
                str = (char*)&buffer[addr - g_va_offset];
                if( check_string(str, str_len) )
                {
                    g_static_strings[g_num_static_strings] = calloc( str_len+1, 1 );
                    memcpy(g_static_strings[g_num_static_strings], str, str_len);
                    ++g_num_static_strings;
                    if( g_num_static_strings + 1 >= g_max_static_strings )
                    {
                        g_max_static_strings *= 2;
                        g_static_strings = realloc(g_static_strings, g_max_static_strings*sizeof(char*));
                    }
                    // printf("woo who\n");
                }
            }
        }
    }
    printf("found %d static strings\n", g_num_static_strings);
}

void find_module_data( const char * buffer )
{
    uint64_t size = 8, i;
    uint64_t offset = 0;
    pElfSections pPcLnTab = getSectionByName(".gopclntab");
    uint64_t *first_entry = (uint64_t*)&buffer[ pPcLnTab->section_header.sh_offset + 8 + size ];
    uint64_t *first_entry_off = (uint64_t*)&buffer[ pPcLnTab->section_header.sh_offset + 8 + size * 2 ];
    uint64_t *addr_func = (uint64_t*)&buffer[pPcLnTab->section_header.sh_offset + (*first_entry_off)];
    // uint64_t md_va_offset = 
    if( *addr_func == *first_entry)
    {
        printf("confirmed gopclntab\n");
        pElfSections pNoPtrData = getSectionByName(".noptrdata");
        for( i = 0; i < pNoPtrData->section_header.sh_size; i += sizeof(uint64_t) )
        {
            uint64_t *value = (uint64_t *)&buffer[pNoPtrData->section_header.sh_offset + i];

            if( *value == pPcLnTab->section_header.sh_addr )
            {
                offset = i;
                g_pmd = (pModuleData)&buffer[pNoPtrData->section_header.sh_offset+offset];
                printf("found module data\n");
                break;
            }
        }
    }
    printf("fin\n");
    // uint64_t *first_entry = (uint64_t*)&buffer[8];
}

// uint8_t test_data[] = 
// {
//     0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//     0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//     0xef, 0xdf, 0xa5, 0x65, 0x00, 0x08, 0x08, 0x36,
//     0x10, 0x7d, 0x8b, 0x01, 0x00, 0x00, 0x00, 0x00,
//     0x10, 0x67, 0x88, 0x00, 0x00, 0x00, 0x00, 0x00,
//     0xa4, 0x5c, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
//     0x80, 0xff, 0x78, 0x00, 0x00, 0x00, 0x00, 0x00,
//     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
// };

int main( int argc, char ** argv )
{
    long lSize = 0;
    FILE *fp = NULL;
    char *buffer = NULL;
    int i;
    // pRType rt;
    
    // printf( "elf_parser: sizeof(rt)=%lx\n", sizeof(rt) );
    // rt = &test_data[0];
    
    fp = fopen("/home/mhartzell/malware/electroRat/er_lin_1", "rb");
    fseek( fp, 0L, SEEK_END );
    lSize = ftell( fp );
    rewind( fp );

    buffer = malloc( lSize );
    fread( buffer, lSize, 1, fp );
    fclose( fp );

    read_elf_header( buffer );

    find_module_data( buffer );
    
    parse_static_strings( buffer );
    parse_file_tab( buffer );
    parse_func_tab( buffer );
    parse_dynamic_strings( buffer );
    parse_itab_symbols( buffer );
    parse_structs( buffer );

    printf("found %d dynamic strings\n", g_num_dynamic_strings);
    free(buffer);
    free(g_sections);
    for( i = 0; i < g_num_static_strings; ++i )
    {
        free( g_static_strings[i] );
    }
    free(g_static_strings );

    for( i = 0; i < g_num_dynamic_strings; ++i )
    {
        free( g_dynamic_strings[i] );
    }
    free(g_dynamic_strings );

    for( i = 0; i < g_num_file_tab; ++i )
    {
        free( g_file_tab[i] );
    }
    free( g_file_tab );

    for( i = 0; i < g_num_func_tab; ++i )
    {
        free( g_func_tab[i] );
    }
    free( g_func_tab );

    for( i = 0; i < g_num_symtab_symbols; ++i )
    {
        // if( strstr(g_symtab_symbols[i], "go.itab") )
        // {
        //     printf("%s\n", g_symtab_symbols[i]);
        // }
        free( g_symtab_symbols[i] );
    }
    free( g_symtab_symbols );

    return 0;
}
#include <stdio.h>
#include <elf.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <string.h>
#include "encodings.h"

// source: https://wiki.osdev.org/DWARF#Relocation
/* Source:
 * The content of a the debug sections is broken down by compilation units
 *
*/

typedef struct __attribute__((packed)) {  
    uint32_t length;
    uint16_t version;
    uint8_t address_size;
    uint8_t segment_selector_size;
    uint32_t header_length; 
    uint8_t min_instruction_length; // segment selector
    uint8_t max_ops_per_instruction;
    uint8_t default_is_smt; //
    int8_t line_base;
    uint8_t line_range;
    uint8_t opcode_base;
    uint8_t std_opcode_lengths[12]; // this can changes, if opcode_base is increased
} DebugLineHeader;

#define DW_FORM_string 0x08 // string


unsigned int decode_uleb128(uint8_t **ptr);
Elf64_Shdr * get_section(Elf64_Shdr **shdr_array, uint16_t sh_num, const char * cmp, char *str_tab); 

int main(int argc, char **argv) {

    if (argc != 2) {
        printf("Usage: ./%s <path_to_elf>\n", argv[0]);
        return 1;
    }

    char *path = argv[1];

    // open the file
    // read the file
    // parse the elf header
    // find the program headers
    // print the number of loadable segmentskjk

    int fd = open(path, O_RDONLY);
    if (fd == -1) {
        printf("failed to open file %s\n", path);
        return -1;
    }

    struct stat sb;
    if (fstat(fd, &sb) == -1) {
        printf("failed to get stat\n");
        return -1;
    }

    size_t filesize = sb.st_size;

    void *elf_bytes = mmap(NULL, filesize, PROT_READ, MAP_PRIVATE, fd, 0);
    if (elf_bytes == MAP_FAILED) {
        printf("failed to mmap file\n");
        return -1;
    }

    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)elf_bytes;
    Elf64_Addr entry = ehdr->e_entry;
    Elf64_Off shoff = ehdr->e_shoff; // section header offset(in bytes) from the elf header
    uint16_t shnum = ehdr->e_shnum; // number of section headers
    uint16_t shstrndx = ehdr->e_shstrndx; //string table section index

    printf("Elf entrypoint: 0x%lx\n", entry);
    printf("Elf section header offset: 0x%lx\n", shoff);
    printf("Number of section headers: %u\n", shnum);

    // Get pontr to section header array
    Elf64_Shdr *shdr_array = (Elf64_Shdr *)((char *) elf_bytes + shoff);
    // Get the string table section header
    Elf64_Shdr *shstrtab = &shdr_array[shstrndx];
    // Get pointer to string table data
    printf("this is strtab");
    char *strtab = (char *)elf_bytes + shstrtab->sh_offset;

    Elf64_Shdr *sh = get_section(&shdr_array, shnum, ".debug_line", strtab);
    if (sh == NULL) {
        return -1;
    }

    void * ptr1 = (elf_bytes + sh->sh_offset);
    // line number program address start
    uint8_t *lineNumber_ptr = (uint8_t *) (ptr1 + 42);

   /* 
    * in the case that I do use a struct
    DebugLineHeader *data = (DebugLineHeader *) (ptr1);
    */

    // length
    uint32_t *len = (uint32_t *) (ptr1); 
    // dwarf version
    uint16_t *version = (uint16_t *) (ptr1 + 4);
    // address size
    uint8_t *addy = (uint8_t *) (ptr1 + 6);
    // seg selector size
    uint8_t *seg_size = (uint8_t *) (ptr1 + 7);
    // header length
    uint32_t *header_len = (uint32_t *) (ptr1 + 8);
    // min instruction length
    uint8_t *min_ins_len = (uint8_t *) ((void *)header_len) + 4;
    // max operation per instruction
    uint8_t *max_op_inst = (uint8_t *) ((void *)min_ins_len) + 1;
    // default is_st_mt
    uint8_t *def_is_stmt = (uint8_t *) ((void *)max_op_inst) + 1;
    // line base
    int8_t *line_base = (int8_t *) ((void *)def_is_stmt)+1;
    // line range
    uint8_t *line_range = (uint8_t *) ((void *)line_base)+1;
    // opcode base
    uint8_t *opcode_base = (uint8_t *) ((void *)line_range)+1;
    // standard opcode len
    uint8_t *std_opcode_len = (uint8_t *) ((void *)opcode_base)+1;
    // directory entry format
    uint8_t *dir_ent_fmt = std_opcode_len + (*opcode_base - 1);
    // directory entry format sequence
    uint8_t *dir_ent_fmt_seq = dir_ent_fmt + 1;


    size_t size = (size_t) sh->sh_size;

    puts("Raw dump of debug contents of section .debug_line:");
    puts("");
    printf("   %-30s %u\n", "Length:", *len);
    printf("   %-30s %u\n", "Dwarf version:", *version);
    printf("   %-30s %u\n", "Header length:", *header_len);
    printf("   %-30s %u\n", "Address size (bytes):", *addy);
    printf("   %-30s %u\n", "Segment Selector (bytes):", *seg_size);
    printf("   %-30s %u\n", "Minimun Instruction Length:", *min_ins_len);
    printf("   %-30s %u\n", "Maximum Ops per Instruction:", *max_op_inst);
    printf("   %-30s %u\n", "Initial values of 'is_stmt':", *def_is_stmt);
    printf("   %-30s %d\n", "Line Base:", *line_base);
    printf("   %-30s %u\n", "Line Range:", *line_range);
    printf("   %-30s %u\n", "Opcode Base:", *opcode_base);


    // Parse the opcodes
    puts("");
    puts(" Opcodes");

    for(int k = 0; k < *opcode_base - 1; k++) {
        printf("   Opcode %d has %u args\n", k+1, std_opcode_len[k]);
    }


    printf("   %-30s %u\n", "Directory entry Format:", *dir_ent_fmt);
    uint8_t *ptr3 = dir_ent_fmt_seq;
    for (int i = 0; i < *dir_ent_fmt; i++) {
        uint8_t ct = decode_uleb128(&ptr3);
        uint8_t fc = decode_uleb128(&ptr3);
        printf("   %x  %x\n", ct, fc);

    }
    // directories count
    uint8_t *dir_count = ptr3;
    //printf("Directories count: %lx\n", decode_uleb128(&dir_count));
    uint8_t dc = decode_uleb128(&dir_count);
    uint8_t *directories = dir_count;

    // now we fine the debug_line_str section addr

    sh = get_section(&shdr_array, shnum, ".debug_line_str", strtab);
    if (sh == NULL) {
        return -1;
    }
    
    uint8_t * db_lstr = (uint8_t *)(elf_bytes + sh->sh_offset);
    uint8_t * ptr5 = directories;
    for (uint64_t i = 0; i < dc; i++) {
        uint32_t offset = *(uint32_t *)ptr5;
        ptr5 +=4;

        char *dir_name = (char *)(db_lstr + offset);
        printf("  Directory[%lu]: offset=0x%x -> \"%s\"\n", i, offset, dir_name);
    }

    // file name entry format count
    uint8_t *file_name_entry_fmt_count = ptr5;
    printf("File Name Entry Format Count: %d\n", *file_name_entry_fmt_count);

    // file name entry format
    uint8_t *file_entry_format = ptr5;
    ptr5++;
    for (int i = 0; i < *file_name_entry_fmt_count; i++) {
        uint8_t ct = decode_uleb128(&ptr5);
        uint8_t fc = decode_uleb128(&ptr5);
        printf("   %x  %x\n", ct, fc);
    }


    return 0;
}

Elf64_Shdr * get_section(Elf64_Shdr **shdr_array, uint16_t sh_num, const char * cmp, char *str_tab) {

    // Now iterate through all section headers
    for (int i = 0; i < sh_num; i++) {
        
        Elf64_Shdr *sh = &(*shdr_array)[i];
        char *name = str_tab + sh->sh_name;

        if (strcmp(name, cmp) == 0) {
            /*
            printf("%s section found\n", cmp);
            printf("    Type: 0x%x\n", sh->sh_type);
            printf("    Offset: 0x%lx\n", sh->sh_offset);
            printf("    Size: 0x%lx\n", sh->sh_size);
            */
            
            if (sh->sh_type == SHT_PROGBITS) {
                return sh;
            }
        }
    }
    return NULL;

}

unsigned char get_next_bytes_in_input() {


}

/*
result = 0;
shift = 0;
unsigned char byte;
do {
  byte = get_next_byte_in_input();
  result |= (byte & 0x7f) << shift; * low-order 7 bits of value 
  shift += 7;
} while ((byte & 0x80) != 0); get high-order bit of byte 
*/
unsigned int decode_uleb128(uint8_t **ptr){

    uint64_t result = 0;
    int shift = 0;
    uint8_t byte;
    do {
        byte = **ptr;
        (*ptr)++;
        result |= (byte & 0x7f) << shift; // low-order 7 bites of value
        shift += 7;
    } while ((byte & 0x80)); // get high-order bit of byte
                                  //
    //printf("result : %x\n", result);
    return result;
}





































#include <string.h>
#include <stdbool.h>

enum segment_type {
  PT_LOAD = 0x1,
  PT_UNKNOWN,
};

#define EI_NIDENT 16

struct elf_header {
  unsigned char e_ident[EI_NIDENT];
  uint16_t      e_type;
  uint16_t      e_machine;
  uint32_t      e_version;
  uint64_t      e_entry;
  uint64_t      e_phoff;
  uint64_t      e_shoff;
  uint32_t      e_flags;
  uint16_t      e_ehsize;
  uint16_t      e_phentsize;
  uint16_t      e_phnum;
  uint16_t      e_shentsize;
  uint16_t      e_shnum;
  uint16_t      e_shstrndx;
};

struct elf_segment {
  uint32_t p_type;
  uint32_t p_flags;
  uint64_t p_offset;
  uint64_t p_vaddr;
  uint64_t p_paddr;
  uint64_t p_filesz;
  uint64_t p_memsz;
  uint64_t p_align;
};

int elf_parse_header(struct elf_header *elfh, uint8_t *elf)
{
  memcpy(&elfh->e_ident, elf, 16);
  memcpy(&elfh->e_type, elf + 0x10, 2);
  memcpy(&elfh->e_machine, elf + 0x12, 2);
  memcpy(&elfh->e_version, elf + 0x14, 4);
  memcpy(&elfh->e_entry, elf + 0x18, 8);
  memcpy(&elfh->e_phoff, elf + 0x20, 8);
  memcpy(&elfh->e_shoff, elf + 0x28, 8);
  memcpy(&elfh->e_flags, elf + 0x30, 4);
  memcpy(&elfh->e_ehsize, elf + 0x34, 2);
  memcpy(&elfh->e_phentsize, elf + 0x36, 2);
  memcpy(&elfh->e_phnum, elf + 0x38, 2);
  memcpy(&elfh->e_shentsize, elf + 0x3A, 2);
  memcpy(&elfh->e_shnum, elf + 0x3C, 2);
  memcpy(&elfh->e_shstrndx, elf + 0x3E, 2);

  return 0;
}

int elf_parse_segment(struct elf_header *elfh, struct elf_segment *elfs,
    size_t number, uint8_t *elf)
{
  uint64_t segment_offset = elfh->e_phoff + (number * elfh->e_phentsize);

  memcpy(&elfs->p_type, elf + segment_offset, 4);
  memcpy(&elfs->p_flags, elf + segment_offset + 0x4, 4);
  memcpy(&elfs->p_offset, elf + segment_offset + 0x8, 8);
  memcpy(&elfs->p_vaddr, elf + segment_offset + 0x10, 8);
  memcpy(&elfs->p_paddr, elf + segment_offset + 0x18, 8);
  memcpy(&elfs->p_filesz, elf + segment_offset + 0x20, 8);
  memcpy(&elfs->p_memsz, elf + segment_offset + 0x28, 8);
  memcpy(&elfs->p_align, elf + segment_offset + 0x30, 8);

  return 0;
}

// it's the responsability of the caller to check if the virtual address
// is smaller than the dst size. Otherwise, we have an out-of-memory write
int elf_load_segment(struct elf_segment *elfs, uint8_t *dst, uint8_t *elf)
{
  memcpy(dst + elfs->p_vaddr, elf + elfs->p_offset, elfs->p_filesz);

  return 0;
}

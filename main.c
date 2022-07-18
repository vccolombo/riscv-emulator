#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#include "elfparser.h"

#define SYS_close 57
#define SYS_lseek 62
#define SYS_read 63
#define SYS_write 64
#define SYS_fstat 80
#define SYS_exit 93
#define SYS_kill 129
#define SYS_times 153
#define SYS_getpid 172
#define SYS_open 1024
#define SYS_unlink 1026

#define BAD_INSN 0x0

#define N_REGS 33
#define PC 32

struct context {
  uint64_t regs[N_REGS];
  uint8_t *mem;
};

void out_debug(struct context* ctx, uint32_t insn)
{
#ifdef DEBUG
  printf("insn: 0x%08x\n", insn);
  for (int i = 0; i < N_REGS - 1; i++) {
    printf("x%02d: 0x%lx\t", i, ctx->regs[i]);
    if ((i + 1) % 4 == 0) {
      printf("\n");
    }
  }
  printf("pc: 0x%lx\n", ctx->regs[PC]);
  printf("\n");
#endif
}

uint32_t extract_32(uint32_t from, int start, int len)
{
  return (from >> start) & ~(~0 << len);
}

uint32_t get_32(uint8_t *mem)
{
  return *((uint32_t*)mem);
}

struct itype {
  uint8_t rd;
  uint8_t rs1;
  uint64_t imm;
};

struct utype {
  uint8_t rd;
  uint64_t imm;
};

struct itype decode_itype(uint32_t insn) {
  struct itype decoded = {
    .rd = extract_32(insn, 7, 5),
    .rs1 = extract_32(insn, 15, 5),
    .imm = extract_32(insn, 20, 12),
  };

  return decoded;
}

struct utype decode_utype(uint32_t insn) {
  struct utype decoded = {
    .rd = extract_32(insn, 7, 5),
    .imm = extract_32(insn, 12, 20),
  };

  return decoded;
}

int lui(struct context *ctx, uint32_t insn)
{
  ctx->regs[PC] += 4;

  return 0;
}

int auipc(struct context *ctx, uint32_t insn)
{
  struct utype decoded = decode_utype(insn);
  uint32_t imm = decoded.imm << 12;
  ctx->regs[decoded.rd] = ctx->regs[PC] + imm;

  ctx->regs[PC] += 4;

  return 0;
}

int addi(struct context *ctx, uint32_t insn)
{
  struct itype decoded = decode_itype(insn);

  uint64_t imm = (uint64_t)decoded.imm << 51 >> 51;
  ctx->regs[decoded.rd] = ctx->regs[decoded.rs1] + imm;

  ctx->regs[PC] += 4;

  return 0;
}

int ecall(struct context *ctx, uint32_t insn)
{
  switch (ctx->regs[17]) {
    case SYS_write:
      out_debug(ctx, insn);
      ctx->regs[10] = write(ctx->regs[10], &ctx->mem[ctx->regs[11]], ctx->regs[12]);
      break;
    case SYS_exit:
      exit(ctx->regs[10]);
      assert("Should not reach here\n" && false);
    default:
      fprintf(stderr, "Syscall not implemented\n");
      exit(-1);
  }

  ctx->regs[PC] += 4;

  return 0;
}

typedef int (*routine_t)(struct context*, uint32_t);

routine_t decode(uint32_t insn)
{
  uint32_t funct3, funct12;
  uint32_t opcode = extract_32(insn, 0, 7);
  switch (opcode) {
    case 0b110111: // LUI
      return &lui;
    case 0b0010111: // AUIPC
      return &auipc;
    case 0b0010011: // OP_IMM
      funct3 = extract_32(insn, 12, 3);
      switch (funct3) {
        case 0b000: // ADDI
          return &addi;
        default:
          break;
      }
      assert("Should not reach here" && false);
    case 0b1110011: // SYSTEM
      funct3 = extract_32(insn, 12, 3);
      switch (funct3) {
        case 0b000: // PRIV
          funct12 = extract_32(insn, 20, 12);
          switch (funct12) {
            case 0b0: // ECALL
              return &ecall;
            default:
              break;
          }
          assert("Should not reach here" && false);
        default:
          break;
      }
      assert("Should not reach here" && false);
    default:
      break;
  }

  return BAD_INSN;
}

void load_all_segments(struct elf_header *elfh, uint8_t *dst, uint8_t *elf)
{
  for (int i = 0; i < elfh->e_phnum; i++) {
    struct elf_segment elfs;
    elf_parse_segment(elfh, &elfs, i, elf);
    if (elfs.p_type == PT_LOAD) {
      elf_load_segment(&elfs, dst, elf);
    }
  }
}

// returns the entry point
uint64_t load_elf(char *path, uint8_t *dst)
{
  int err;
  int fd = open(path, O_RDONLY);
  if (fd == -1) {
    return -errno;
  }

  struct stat sb;
  err = fstat(fd, &sb);
  if (err == -1) {
    return -errno;
  }

  uint8_t *elf = malloc(sb.st_size);
  err = read(fd, elf, sb.st_size);
  if (err == -1) {
    return -errno;
  }

  struct elf_header elfh;
  elf_parse_header(&elfh, elf);
  load_all_segments(&elfh, dst, elf);

  free(elf);
  close(fd);

  return elfh.e_entry;
}

int main(int argc, char* argv[])
{
  int entry_point;
  struct context ctx = {{ 0 }};

  if (argc < 2) {
    fprintf(stderr, "Usage: %s [PATH]\n", argv[0]);
    return -1;
  }

  uint8_t *mem = malloc(0x100000);
  entry_point = load_elf(argv[1], mem);
  if (entry_point < 0) {
    fprintf(stderr, "Unable to read file: ERROR %d\n", entry_point);
    return entry_point;
  }

  ctx.regs[PC] = entry_point;
  ctx.mem = mem;

  bool shutdown = false;
  while (!shutdown) {
    int insn = get_32(&mem[ctx.regs[PC]]);
    routine_t dispatch = decode(insn);
    if ((uint64_t)dispatch == BAD_INSN) {
      fprintf(stderr, "Bad instruction 0x%08x at address 0x%016lx\n",
          insn, ctx.regs[PC]);
      shutdown = true;
      continue;
    }
    dispatch(&ctx, insn);
    out_debug(&ctx, insn);
  }

  free(mem);
}

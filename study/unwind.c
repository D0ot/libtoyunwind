/* I like big *.c */

#define _GNU_SOURCE

#include <link.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/ucontext.h>
#include <ucontext.h>
#include <dwarf.h>

typedef uint8_t u8;
typedef int8_t i8;
typedef uint16_t u16;
typedef int16_t i16;
typedef uint32_t u32;
typedef int32_t i32;
typedef uint64_t u64;
typedef int64_t i64;


#define CIE_AUG_STR_z 0x01
#define CIE_AUG_STR_L 0x02
#define CIE_AUG_STR_P 0x04
#define CIE_AUG_STR_R 0x08

struct cie_entry {
	u32 length;
	u32 cie_id;
	u64 ext_length; // optional
	char *aug_str;
	u8 version;
	u8 aug_flags;

	u64 code_align_factor;
	i64 data_align_factor;

	u64 ra;

	u64 aug_length;
	u8 *aug_data;

	u8 *init_insts;
	u64 init_insts_sz;

	u8 fde_ptr_enc;
	u8 lsda_ptr_enc;
	u8 personality_enc;
	u64 personality_handler;
};

struct fde_entry {
	u32 length;
	u64 ext_length; // optional
	u32 cie_ptr;
	i64 pc_begin;
	i64 pc_range;
	u64 aug_len;
	u8 *aug_data;
	u64 cfi_ptr;
	u64 cfi_sz;
};

struct eh_frame_hdr_raw {
	u8 version;
	u8 eh_frame_ptr_enc;
	u8 fde_count_enc;
	u8 table_enc;
	u8 encode[];
} __attribute__((packed));


struct eh_decode_ctx {
	u64 pc;
	u64 text;
	u64 data;
	u64 func;
};

struct tunw_context_t {
	ucontext_t uctx;
};

struct tuwn_cursor_t {
	u64 rip;
	u64 ra;
	struct fde_entry fde;
};

struct find_segment_data {
	ElfW(Phdr) dlpi_phdr;
	ElfW(Addr) base_addr;
	uint64_t pc;
};

#define DW_EH_REGS_MAX 64

enum eh_reg_type {
	REG_UNDEF,
	REG_SAME_VAL,
	REG_OFFSET,
	REG_VAL_OFFSET,
	REG_REGISTER,
	REG_EXP,
	REG_VAL_EXP
};

struct eh_cfi_row {
	u64 loc;
	i64 reg_offset[DW_EH_REGS_MAX];
	enum eh_reg_type reg_type[DW_EH_REGS_MAX];
	i64 cfa_reg;
	i64 cfa_offset;
};

struct eh_cfi_ctx {
	struct cie_entry *cie;
	struct eh_cfi_row *cur;
	struct eh_cfi_row *init;

	struct eh_cfi_row *stack;

	struct eh_cfi_row *hist;
	u64 hist_len;
};

u64 align_address_unit(u64 ptr) {
	static_assert(sizeof(void*) == 8, "address unit size is not 8");
	return (ptr + 7) & ~(0x8 - 1);
}

i32 read_leb128(u8 *bytes, u64 *val) {
	i32 i = 0;
	i32 shift = 0;
	u8 byte;

	*val = 0;

	do {
		byte = bytes[i];
		*val |= (byte & 0x7F) << shift;
		shift += 7;
		++i;
	} while (byte & 0x80);

	assert(shift < sizeof(u64) * 8);
	return i;
}

i32 read_sleb128(u8 *bytes, i64 *val) {
	i32 i = 0;
	i32 shift = 0;
	u8 byte;

	*val = 0;
	do {
		byte = bytes[i];
		*val |= (byte & 0x7F) << shift;
		shift += 7;
		++i;
	} while (byte & 0x80);

	assert(shift < sizeof(u64) * 8);

	if (byte & 0x40) {
		*val |= (~0 << shift);
	}

	return i;
}

void print_eh_cfi_row(struct eh_cfi_ctx *ctx) {
	printf("%16lx cfa=[%lx+%ld]\t", ctx->cur->loc, ctx->cur->cfa_reg, ctx->cur->cfa_offset);
	for (i32 i = 0; i < DW_EH_REGS_MAX; ++i) {
		if (ctx->cur->reg_type[i] == REG_OFFSET) {
			printf("reg_%d=[c + %ld] ", i, ctx->cur->reg_offset[i]);
		}
	}
	putchar('\n');
}

void cfi_new_col(struct eh_cfi_ctx *ctx, u64 loc) {
	struct eh_cfi_row *tmp;
	ctx->hist_len++;
	tmp = realloc(ctx->hist, sizeof(struct eh_cfi_row) * ctx->hist_len);
	assert(tmp != NULL);
	ctx->hist = tmp;
	ctx->cur = ctx->hist + ctx->hist_len - 1;
	memcpy(ctx->cur, ctx->cur - 1, sizeof(struct eh_cfi_row));
	ctx->cur->loc = loc;
}
 
i32 cfi_advance_loc(struct eh_cfi_ctx *ctx, i8 offset) {
	cfi_new_col(ctx, ctx->cur->loc + offset);
	return 0;
};

i32 cfi_offset(struct eh_cfi_ctx *ctx, u8 low6bits, u8 *bytes) {
	i32 ret;
	ctx->cur->reg_type[low6bits] = REG_OFFSET;
	ret = read_leb128(bytes, (u64 *)&(ctx->cur->reg_offset[low6bits]));
	assert(ctx->cur->reg_offset[low6bits] > 0);
	return ret;
}

i32 cfi_restore(struct eh_cfi_ctx *ctx, u64 low6bits) {
	ctx->cur->reg_type[low6bits] = ctx->init->reg_type[low6bits];
	ctx->cur->reg_offset[low6bits] = ctx->init->reg_type[low6bits];
	return 1;
}

typedef i32 (*cfi_func)(struct eh_cfi_ctx *ctx, u8 *bytes);

i32 cfi_nop(struct eh_cfi_ctx *ctx, u8 *bytes) {
	return 0;
}

i32 cfi_set_loc(struct eh_cfi_ctx *ctx, u8 *bytes) {
	cfi_new_col(ctx, *(u64 *)bytes + ctx->cur->loc);
	return sizeof(void*);
}

i32 cfi_advance_loc1(struct eh_cfi_ctx *ctx, u8 *bytes) {
	cfi_new_col(ctx, *(i8 *)bytes + ctx->cur->loc);
	return 1;
}

i32 cfi_advance_loc2(struct eh_cfi_ctx *ctx, u8 *bytes) {
	cfi_new_col(ctx, *(i16 *)bytes + ctx->cur->loc);
	return 2;
}

i32 cfi_advance_loc4(struct eh_cfi_ctx *ctx, u8 *bytes) {
	cfi_new_col(ctx, *(i32 *)bytes + ctx->cur->loc);
	return 4;
}

i32 cfi_offset_ext(struct eh_cfi_ctx *ctx, u8 *bytes) {
	u64 reg, offset;
	i32 ret = 0;
	ret += read_leb128(bytes, &reg);
	ret += read_leb128(bytes + ret, &offset);
	return ret;
}


i32 cfi_restore_ext(struct eh_cfi_ctx *ctx, u8 *bytes) {
	i32 ret = 0;
	u64 reg;
	ret = read_leb128(bytes, &reg);
	ctx->cur->reg_type[reg] = ctx->init->reg_type[reg];
	ctx->cur->reg_offset[reg] = ctx->init->reg_type[reg];
	return ret;
}

i32 cfi_remember_state(struct eh_cfi_ctx *ctx, u8 *bytes) {
	assert(0);
	return 0;
}

i32 cfi_restore_state(struct eh_cfi_ctx *ctx, u8 *bytes) {
	assert(0);
	return 0;
}

i32 cfi_undef(struct eh_cfi_ctx *ctx, u8 *bytes) {
	i32 ret = 0;
	u64 reg;
	ret = read_leb128(bytes, &reg);
	ctx->cur->reg_type[reg] = REG_UNDEF;
	return ret;
}

i32 cfi_same_value(struct eh_cfi_ctx *ctx, u8 *bytes) {
	i32 ret = 0;
	u64 reg;
	ret = read_leb128(bytes, &reg);
	ctx->cur->reg_type[reg] = REG_SAME_VAL;
	return ret;
}

i32 cfi_register(struct eh_cfi_ctx *ctx, u8 *bytes) {
	i32 ret = 0;
	u64 reg1, reg2;
	ret += read_leb128(bytes, &reg1);
	ret += read_leb128(bytes + ret, &reg2);
	ctx->cur->reg_type[reg1] = REG_REGISTER;
	ctx->cur->reg_offset[reg1] = reg2;
	return ret;
}


i32 cfi_def_cfa(struct eh_cfi_ctx *ctx, u8 *bytes) {
	u64 reg, offset;
	i32 ret = 0;
	ret = read_leb128(bytes, &reg);
	ret += read_leb128(bytes, &offset);
	ctx->cur->cfa_reg = reg;
	ctx->cur->cfa_offset = offset;
	return ret;
}

i32 cfi_def_cfa_register(struct eh_cfi_ctx *ctx, u8 *bytes) {
	u64 reg;
	i32 ret = 0;
	ret = read_leb128(bytes, &reg);
	ctx->cur->cfa_reg = reg;
	return ret;
}

i32 cfi_def_cfa_offset(struct eh_cfi_ctx *ctx, u8 *bytes) {
	u64 offset;
	i32 ret = 0;
	ret = read_leb128(bytes, &offset);
	ctx->cur->cfa_offset = offset;
	return ret;
}

i32 cfi_def_cfa_expression(struct eh_cfi_ctx *ctx, u8 *bytes) {
	assert(0);
	return 0;
}

i32 cfi_expression(struct eh_cfi_ctx *ctx, u8 *bytes) {
	assert(0);
	return 0;
}

i32 cfi_offset_ext_sf(struct eh_cfi_ctx *ctx, u8 *bytes) {
	i64 offset;
	u64 reg;
	i32 ret = 0;
	ret += read_leb128(bytes, &reg);
	ret += read_sleb128(bytes, &offset);
	ctx->cur->reg_offset[reg] = offset * ctx->cie->data_align_factor;
	return ret;
}

i32 cfi_def_cfa_sf(struct eh_cfi_ctx *ctx, u8 *bytes) {
	i64 offset;
	u64 reg;
	i32 ret = 0;
	ret += read_leb128(bytes, &reg);
	ret += read_sleb128(bytes, &offset);
	ctx->cur->cfa_offset = offset * ctx->cie->data_align_factor;
	ctx->cur->cfa_reg = reg;
	return ret;
}

i32 cfi_def_cfa_offset_sf(struct eh_cfi_ctx *ctx, u8 *bytes) {
	i64 offset;
	i32 ret = 0;
	ret += read_sleb128(bytes, &offset);
	ctx->cur->cfa_offset = offset * ctx->cie->data_align_factor;
	return ret;
}
i32 cfi_val_offset(struct eh_cfi_ctx *ctx, u8 *bytes) {
	u64 reg, offset;
	i32 ret = 0;
	ret += read_leb128(bytes, &reg);
	ret += read_leb128(bytes, &offset);
	ctx->cur->reg_type[reg] = REG_VAL_OFFSET;
	ctx->cur->reg_offset[reg] = offset;
	return ret;
}

i32 cfi_val_offset_sf(struct eh_cfi_ctx *ctx, u8 *bytes) {
	u64 reg;
	i64 offset;
	i32 ret = 0;
	ret += read_leb128(bytes, &reg);
	ret += read_sleb128(bytes, &offset);
	ctx->cur->reg_type[reg] = REG_VAL_OFFSET;
	ctx->cur->reg_offset[reg] = offset * ctx->cie->data_align_factor;
	return 0;
}

i32 cfi_val_expression(struct eh_cfi_ctx *ctx, u8 *bytes) {
	return 0;
}

cfi_func cfi_func_tables[] = {
	cfi_nop,
	cfi_set_loc,
	cfi_advance_loc1,
	cfi_advance_loc2,
	cfi_advance_loc4,
	cfi_offset_ext,
	cfi_restore_ext,
	cfi_remember_state,
	cfi_undef,
	cfi_same_value,
	cfi_register,
	cfi_remember_state,
	cfi_restore_state,
	cfi_def_cfa,
	cfi_def_cfa_register,
	cfi_def_cfa_offset,
	cfi_def_cfa_expression,
	cfi_expression,
	cfi_offset_ext_sf,
	cfi_def_cfa_sf,
	cfi_def_cfa_offset_sf,
	cfi_val_offset,
	cfi_val_offset_sf,
	cfi_val_expression,
};


i32 cfi_single_step(struct eh_cfi_ctx *ctx, u8 *bytes) {

	u8 *ptr = bytes;
	i32 ret = 0;
	u8 opcode = ptr[0];
	u8 high2bits = opcode & 0xC0;
	u8 low6bits = opcode & 0x3F;
	if (high2bits) {
		switch (high2bits) {
			case DW_CFA_advance_loc:
				ret = cfi_advance_loc(ctx, low6bits);
				break;
			case DW_CFA_offset:
				ret = cfi_offset(ctx, low6bits, ptr);
				break;
			case DW_CFA_restore:
				ret = cfi_restore(ctx, low6bits);
				break;
		}
	} else {
		if (low6bits <= DW_CFA_val_expression) {
			ret = cfi_func_tables[low6bits](ctx, bytes);
		}
	}

	return ret + 1;
}

void cfi_steps(struct eh_cfi_ctx *ctx, u8 *bytes, u64 len) {
	u64 acc_offset = 0;
	
	while (acc_offset < len) {
		acc_offset += cfi_single_step(ctx, bytes + acc_offset);
	}
	assert(acc_offset == len);
};

struct eh_cfi_ctx *cfi_ctx_init(struct cie_entry *cie) {
	struct eh_cfi_ctx *ctx;
	ctx = malloc(sizeof(struct eh_cfi_ctx));
	memset(ctx, 0, sizeof(struct eh_cfi_ctx));

	ctx->hist_len = 1;
	ctx->hist = malloc(sizeof(struct eh_cfi_row) * ctx->hist_len);
	memset(ctx->hist, 0, sizeof(struct eh_cfi_row) * ctx->hist_len);

	ctx->init = malloc(sizeof(struct eh_cfi_row));
	memset(ctx->hist, 0, sizeof(struct eh_cfi_row));

	ctx->stack = NULL;
	ctx->cur = ctx->hist;

	cfi_steps(ctx, cie->init_insts, cie->init_insts_sz);
	memcpy(ctx->init, ctx->hist, sizeof(struct eh_cfi_row));
	return ctx;
}

void cfi_ctx_push(struct eh_cfi_ctx *ctx) {
	// no impl
	assert(0);
}

void cfi_ctx_pop(struct eh_cfi_ctx *ctx) {
	// no impl
	assert(0);
}

void cfi_ctx_done(struct eh_cfi_ctx *ctx) {
	free(ctx->hist);
	if (ctx->stack) {
		free(ctx->stack);
	}
	free(ctx->init);
	free(ctx);
}

void test_leb() {

	u8 leb[4] = { 0xe5, 0x8e, 0x26 };
	u64 leb128;
	read_leb128(leb, &leb128);
	u8 sleb[4] = { 0xc0, 0xbb, 0x78 };
	i64 sleb128;
	read_sleb128(sleb, &sleb128);
	printf("%lu %ld\n", leb128, sleb128);
	assert(leb128 == 624485);
	assert(sleb128 == -123456);

}

void print_phdr_name(const struct dl_phdr_info *info) {
	const char *dlpi_name = NULL;

	if (info->dlpi_name == NULL) {
		dlpi_name = NULL;
	} else if (info->dlpi_name[0] == '\0') {
		dlpi_name = "Empty String";
	} else {
		dlpi_name = info->dlpi_name;
	}
	printf("name: [%s]\n", dlpi_name);
}

int find_ehframehdr_cb(struct dl_phdr_info *info, size_t size, void *data) {
	struct find_segment_data *dat = (struct find_segment_data *)data;
	const ElfW(Phdr) *dlpi_phdr_tmp = NULL;
	bool found = false;

	for (i32 i = 0; i < info->dlpi_phnum; ++i) {
		if (info->dlpi_phdr[i].p_type == PT_LOAD) {
			ElfW(Addr) begin_addr = info->dlpi_addr + info->dlpi_phdr[i].p_vaddr;
			ElfW(Addr) end_addr = begin_addr + info->dlpi_phdr[i].p_memsz;

			if (dat->pc >= begin_addr && dat->pc < end_addr) {
				found = true;
				if (dlpi_phdr_tmp) {
					break;
				}
			}
		} else if (info->dlpi_phdr[i].p_type == PT_GNU_EH_FRAME) {
			dlpi_phdr_tmp = &info->dlpi_phdr[i];
			if (found) {
				break;
			}
		}
	}

	if (found) {
		memcpy(&dat->dlpi_phdr, dlpi_phdr_tmp, sizeof(ElfW(Phdr)));
		dat->base_addr = info->dlpi_addr;
		return 1;
	}
	return 0;
}

static i32 read_format_signed(u8 *bytes, u8 enc, i64 *val)
{
	i32 ret = 0;
	switch (enc & 0x0F) {
		case DW_EH_PE_sleb128:
			ret = read_sleb128(bytes, val);
			break;
		case DW_EH_PE_sdata2:
			*val = *((i16*)(bytes));
			ret = 2;
			break;
		case DW_EH_PE_sdata4:
			*val = *((i32*)(bytes));
			ret = 4;
			break;
		case DW_EH_PE_sdata8:
			*val = *((i64*)(bytes));
			ret = 8;
			break;
	}
	return ret;
}

static i32 read_format_unsigned(u8 *bytes, u8 enc, u64 *val) {
	i32 ret = 0;
	switch (enc & 0x0F) {
		case DW_EH_PE_uleb128:
			ret = read_leb128(bytes, val);
			break;
		case DW_EH_PE_udata2:
			*val = *((u16*)(bytes));
			ret = 2;
			break;
		case DW_EH_PE_udata4:
			*val = *((u32*)(bytes));
			ret = 4;
			break;
		case DW_EH_PE_absptr:
		case DW_EH_PE_udata8:
			*val = *((u64*)(bytes));
			ret = 8;
			break;
	}
	return ret;
}

static i32 read_format_encoded(u8 *bytes, u8 enc, i64 *val) {
	i32 ret = 0;

	if (enc & 0x08) {
		ret = read_format_signed(bytes, enc, val);
	} else {
		ret = read_format_unsigned(bytes, enc, (u64 *)val);
		assert(val > 0);
	}
	return ret;
}

static i32 encoded_data_present(u8 enc) {
	return enc != DW_EH_PE_omit;
}

static i32 read_encoded(u8 *bytes, u8 enc, i64 *val, const struct eh_decode_ctx *ctx) {
	i64 tmp;
	i32 ret;
	
	if (enc == DW_EH_PE_omit) {
		return 0;
	}

	ret = read_format_encoded(bytes, enc, &tmp);

	switch (enc & 0xF0) {
		case DW_EH_PE_absptr:
			*val = tmp;
			break;
		case DW_EH_PE_pcrel:
			*val = tmp + ctx->pc;
			break;
		case DW_EH_PE_textrel:
			*val = tmp + ctx->text;
			break;
		case DW_EH_PE_datarel:
			*val = tmp + ctx->data;
			break;
		case DW_EH_PE_funcrel:
			*val = tmp + ctx->func;
			break;
		case DW_EH_PE_aligned:
			*val = align_address_unit(tmp);
			break;
	}
	return ret;
}

struct eh_frame_hdr_raw *get_ehframehdr_raw(const struct find_segment_data *dat) {
	struct eh_frame_hdr_raw *hdr =
			(struct eh_frame_hdr_raw *)(dat->base_addr + dat->dlpi_phdr.p_vaddr);
	return hdr;
}

i32 get_ehframe(const struct eh_frame_hdr_raw *hdr, i32 offset, i64 *val) {
	struct eh_decode_ctx ctx;
	ctx.pc = (u64)&hdr->encode;
	return read_encoded((u8 *)hdr + offset, hdr->eh_frame_ptr_enc, val, &ctx);
}

i32 get_fde_count(const struct eh_frame_hdr_raw *hdr, i32 offset, i64 *val) {
	struct eh_decode_ctx ctx;
	ctx.pc = (u64)&hdr->encode;
	return read_encoded((u8 *)hdr + offset, hdr->fde_count_enc, val, &ctx);
}

i32 find_fde(const struct find_segment_data *dat) {
	return 0;
}

void print_eh_frame_hdr_raw(const struct eh_frame_hdr_raw *hdr) {
	printf("eh_frame_hdr_raw addr = %p\n", hdr);
	printf("eh_frame_hdr_raw first 4 bytes: 0x%x 0x%x 0x%x 0x%x\n", hdr->version,
			 hdr->eh_frame_ptr_enc, hdr->fde_count_enc, hdr->table_enc);
}



// nonzero: return consumed bytes count including the initial instructions
// zero: terminator CIE entry
i64 fill_cie_entry(u64 ehframe_ptr, struct cie_entry *cie) {
	u64 ptr = ehframe_ptr;
	i64 tmp = 0;
	cie->length = *(u32 *)(ptr);
	ptr += 4;
	if (cie->length == 0xffffffff) {
		cie->ext_length = *(u64 *)(ptr);
		ptr += 8;
	} else if (cie->length == 0) {
		return 0;
	} else {
		cie->ext_length = 0;
	}

	cie->cie_id = *(u32 *)(ptr);
	ptr += 4;
	
	if (cie->cie_id != 0) {
		return -1;
	}

	cie->version = *(u8 *)(ptr);
	ptr += 1;

	cie->aug_str = (char *)ptr;

	cie->aug_flags = 0;

	// TODO: more check and sequence problem
	while (*(u8 *)(ptr)) {

		char c = *(char*)ptr;
		if (c == 'z') {
			cie->aug_flags |= CIE_AUG_STR_z;
		} else if (c == 'P') {
			cie->aug_flags |= CIE_AUG_STR_P;
		} else if (c == 'R') {
			cie->aug_flags |= CIE_AUG_STR_R;
		} else if (c == 'L'){
			cie->aug_flags |= CIE_AUG_STR_L;
		}
		++ptr;
	}

	// skip the NUL
	++ptr;

	ptr += read_leb128((u8 *)ptr, &cie->code_align_factor);

	ptr += read_sleb128((u8 *)ptr, &cie->data_align_factor);

	ptr += read_leb128((u8 *)ptr, &cie->ra);

	// the augmentation data is present
	if (cie->aug_flags & CIE_AUG_STR_z) {
		ptr += read_leb128((u8 *)ptr, &cie->aug_length);
		cie->aug_data = (u8 *)ptr;
		ptr += cie->aug_length;

		if (cie->aug_flags & CIE_AUG_STR_R) {
			cie->fde_ptr_enc = cie->aug_data[0];
		}

	}

	cie->init_insts = (u8 *)ptr;

	// TODO: refactor, extract the "instructions sizing and alignment code"
	// tmp is the structure size w/o initial instructions
	tmp = ptr - ehframe_ptr;

	if (cie->ext_length) {
		cie->init_insts_sz = cie->ext_length - (tmp - sizeof(cie->ext_length) - sizeof(cie->length));
	} else {
		cie->init_insts_sz = cie->length - (tmp - sizeof(cie->length));
	}

	// return count of used bytes including initial instructions and padding
	return tmp + cie->init_insts_sz;
}

void print_cie_entry(const struct cie_entry *cie) {
	printf("CIE\n");
}

void print_fde_entry(const struct fde_entry *fde) {
	printf("FDE, 0x%lx, 0x%lx\n", fde->pc_begin, fde->pc_range);
}

// return the sizeof this fde
i64 fill_fde_entry(u64 fde_ptr, const struct cie_entry *cie, struct fde_entry *fde) {
	u64 ptr = fde_ptr;
	i64 tmp = 0;
	u8 fde_ptr_enc;

	fde->length = *(u32 *)(ptr);
	ptr += 4;
	if (fde->length == 0xffffffff) {
		fde->ext_length = *(u64 *)(ptr);
		ptr += 8;
	} else if (fde->length == 0) {
		return 0;
	} else {
		fde->ext_length = 0;
	}

	fde->cie_ptr = *(u32 *)ptr;
	ptr += 4;

	if (fde->cie_ptr == 0) {
		return -1;
	}

	struct eh_decode_ctx ctx;
	ctx.pc = 0xffff;
	ptr += read_encoded((u8 *)ptr, cie->fde_ptr_enc, &fde->pc_begin, &ctx);

	fde->pc_range = *(u32 *)ptr;
	ptr += 4;

	if (cie->aug_flags & CIE_AUG_STR_z) {
		ptr += read_leb128((u8 *)ptr, &fde->aug_len);
		fde->aug_data = (u8 *)ptr;
		ptr += fde->aug_len;
	}

	fde->cfi_ptr = ptr;

	// TODO: refactor, extract the "instructions sizing and alignment code"
	// tmp is the structure size w/o CFI 
	tmp = ptr - fde_ptr;

	if (fde->ext_length) {
		fde->cfi_sz = fde->ext_length - (tmp - sizeof(fde->ext_length) - sizeof(fde->length));
	} else {
		fde->cfi_sz = fde->length - (tmp - sizeof(fde->length));
	}

	// return count of used bytes including CFI and padding
	return tmp + fde->cfi_sz;
}


void print_bst(u64 table_ptr, u8 encode, u64 fde_count, const struct eh_frame_hdr_raw *hdr,
		const struct cie_entry *cie) {
	i64 initval;
	i64 address;
	i64 offset = 0;
	u64 tmp;
	u64 ptr = table_ptr;

	if (encode == DW_EH_PE_omit) {
		return;
	}

	for (i64 i = 0; i < fde_count; ++i) {
		offset = read_format_encoded((u8 *)ptr, encode, &initval);
		ptr += offset;
		offset = read_format_encoded((u8 *)ptr, encode, &address);
		ptr += offset;

		printf("BST pairs:\tinitval = %ld, address = %ld\n", initval, address);

		if ((encode & 0xf0) == DW_EH_PE_pcrel) {
			initval += table_ptr;
			address += table_ptr;
		} else if ((encode & 0xf0) == DW_EH_PE_datarel) {
			initval += (u64)hdr;
			address += (u64)hdr;
		}

		struct fde_entry fde;
		printf("\t\tinitval = %lx, address = %lx\n", initval, address);
		fill_fde_entry(address, cie, &fde);
	}
}

void find_ehframehdr(u64 pc) {
	int ret;
	struct find_segment_data dat;
	dat.pc = pc;
	ret = dl_iterate_phdr(find_ehframehdr_cb, (void *)&dat);

	if (ret) {
		printf("obj base addr = 0x%lx, phdr_vaddr = 0x%lx\n", dat.base_addr,
					 dat.dlpi_phdr.p_vaddr);
	} else {
		printf("Not found\n");
	}

	print_eh_frame_hdr_raw(get_ehframehdr_raw(&dat));

	i64 ehframe_ptr, fde_count;
	struct eh_frame_hdr_raw *hdr = get_ehframehdr_raw(&dat);
	i32 offset = sizeof(struct eh_frame_hdr_raw);

	offset += get_ehframe(hdr, offset, &ehframe_ptr);
	printf("ehframe offset = %d\n", offset);
	offset += get_fde_count(hdr, offset, &fde_count);
	printf("fde_count offset = %d\n", offset);

	printf("ehframe_ptr = %lx, fde_count = %ld\n", ehframe_ptr, fde_count);

	// TODO: how many CIEs in the ehframe_ptr ?
	struct cie_entry cie;
	struct fde_entry fde;
	i64 new_offset = 0;
	u64 ptr = ehframe_ptr;

	bool is_fde = false;
	for(;;) {
		if (is_fde) {
			new_offset = fill_fde_entry(ptr, &cie, &fde);
			if (new_offset == 0) {
				break;
			} else if (new_offset < 0) {
				is_fde = false;
			} else {
				print_fde_entry(&fde);
				ptr += new_offset;
			}

		} else {
			new_offset = fill_cie_entry(ptr, &cie);
			if (new_offset == 0) {
				break;
			} else if (new_offset < 0) {
				is_fde = true;
			} else {
				print_cie_entry(&cie);
				ptr += new_offset;
				is_fde = true;
			}
		}
	}


	print_bst((u64)hdr + offset, hdr->table_enc, fde_count, hdr, (struct cie_entry *)ehframe_ptr);
}

u64 get_pc() {
	ucontext_t ctx;
	getcontext(&ctx);
	return ctx.uc_mcontext.gregs[REG_RIP];
}

int32_t twun_get_context(struct tunw_context_t *ctx) {
	getcontext(&ctx->uctx);
	return 0;
}

int callback(struct dl_phdr_info *info, size_t size, void *data) {
	print_phdr_name(info);

	for (i32 i = 0; i < info->dlpi_phnum; ++i) {
		printf("\t\t header %2d: address=%10p, type = %10x\n", i,
					 (void *)(info->dlpi_addr + info->dlpi_phdr[i].p_vaddr),
					 info->dlpi_phdr[i].p_type);
	}
	return 0;
}

void stack_unwind() { dl_iterate_phdr(callback, NULL); }

void stack_unwind_fast() {
	struct ucontext_t ctx;
	int ret;

	ret = getcontext(&ctx);

	if (ret != 0) {
		perror("getcontext() failed");
		exit(1);
	}

	uint64_t rip = ctx.uc_mcontext.gregs[REG_RIP];

	printf("rip = %p\n", (void *)rip);

	void **rbp = (void **)ctx.uc_mcontext.gregs[REG_RBP];

	while (rbp) {
		printf("rbp = %p, ra = %p\n", rbp, rbp[1]);
		rbp = (void *)rbp[0];
	}
}

int main(int argc, char *argv[]) {
	u64 rip = get_pc();
	printf("rip = %p\n", (void *)rip);
	find_ehframehdr(rip);
	return EXIT_SUCCESS;
}

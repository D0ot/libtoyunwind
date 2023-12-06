/* I like big *.c */

#define _GNU_SOURCE

#include <dwarf.h>
#include <link.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/ucontext.h>
#include <ucontext.h>

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


static i32 read_signed_encoded(u8 *bytes, u8 enc, i64 *val)
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

static i32 read_unsigned_encoded(u8 *bytes, u8 enc, u64 *val) {
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

static i32 read_encoded(u8 *bytes, u8 enc, i64 *val) {
	i32 ret = 0;

	if (enc & 0x08) {
		ret = read_signed_encoded(bytes, enc, val);
	} else {
		ret = read_unsigned_encoded(bytes, enc, (u64 *)val);
		assert(val > 0);
	}
	return ret;
}


struct eh_frame_hdr_raw *get_ehframehdr_raw(const struct find_segment_data *dat) {
	struct eh_frame_hdr_raw *hdr =
			(struct eh_frame_hdr_raw *)(dat->base_addr + dat->dlpi_phdr.p_vaddr);
	return hdr;
}

i32 get_ehframe(const struct eh_frame_hdr_raw *hdr, i32 offset, i64 *val) {
	i64 tmp;
	i32 len = read_encoded((u8*)hdr + offset, hdr->eh_frame_ptr_enc, &tmp);

	switch (hdr->eh_frame_ptr_enc & 0xF0) {
		case 0:
			*val = tmp;
			break;
		case DW_EH_PE_pcrel:
			*val = (u64)(&hdr->encode) + tmp;
			break;
		case DW_EH_PE_textrel:
		case DW_EH_PE_datarel:
		case DW_EH_PE_funcrel:
		case DW_EH_PE_aligned:
			*val = 0;
			break;
	}

	return len;
}

i32 get_fde_count(const struct eh_frame_hdr_raw *hdr, i32 offset, i64 *val) {
	i64 tmp;
	i32 len = read_encoded((u8*)hdr+ offset, hdr->eh_frame_ptr_enc, &tmp);

	switch (hdr->fde_count_enc & 0xF0) {
		case 0:
			*val = tmp;
			break;
		case DW_EH_PE_pcrel:
			*val = (u64)(&hdr->encode) + tmp;
			break;
		case DW_EH_PE_textrel:
		case DW_EH_PE_datarel:
		case DW_EH_PE_funcrel:
		case DW_EH_PE_aligned:
			*val = 0;
			break;
	}
	return len;

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
	return align_address_unit(tmp + cie->init_insts_sz + ehframe_ptr) - ehframe_ptr;
}

void print_cie_entry(const struct cie_entry *cie) {
	printf("CIE\n");
}

void print_fde_entry(const struct fde_entry *fde) {
	printf("FDE, %lx, %lx\n", fde->pc_begin, fde->pc_begin + fde->pc_range);
}

// return the sizeof this fde
i64 fill_fde_entry(u64 fde_ptr, const struct cie_entry *cie, struct fde_entry *fde) {
	u64 ptr = fde_ptr;
	i64 tmp = 0;

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

	ptr += read_encoded((u8 *)ptr, cie->fde_ptr_enc, &fde->pc_begin);

	ptr += read_encoded((u8 *)ptr, cie->fde_ptr_enc, &fde->pc_range);

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
	return align_address_unit(tmp + fde->cfi_sz + fde_ptr) - fde_ptr;
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
		offset = read_encoded((u8 *)ptr, encode, &initval);
		ptr += offset;
		offset = read_encoded((u8 *)ptr, encode, &address);
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

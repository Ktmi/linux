
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/file.h>
#include <linux/bpf_io.h>

/* file_ppos returns &file->f_pos or NULL if file is stream */
static inline loff_t *file_ppos(struct file *file)
{
	return file->f_mode & FMODE_STREAM ? NULL : &file->f_pos;
}

BPF_CALL_2(bpf_io_read, struct bpf_io_buff *, io_buff, u32, count)
{
	int buf_size = io_buff->buf_end - io_buff->buf;
	loff_t pos, *ppos;
	ssize_t ret;
	if (count > buf_size)
		return -EINVAL;
	if ( (ppos = file_ppos(io_buff->filp)) ) {
		pos = *ppos;
		ppos = &pos;
	}
	ret = kernel_read(io_buff->filp, io_buff->buf, count, ppos);
	if (ret >= 0 && ppos)
		io_buff->filp->f_pos = pos;
	return ret;
}

static const struct bpf_func_proto bpf_io_read_proto = {
	.func		= bpf_io_read,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
};

BPF_CALL_2(bpf_io_write, struct bpf_io_buff *, io_buff, u32, count)
{
	int buf_size = io_buff->buf_end - io_buff->buf;
	loff_t pos, *ppos;
	ssize_t ret;
	if (count > buf_size)
		return -EINVAL;
	if ( (ppos = file_ppos(io_buff->filp)) ) {
		pos = *ppos;
		ppos = &pos;
	}
	ret = kernel_write(io_buff->filp, io_buff->buf, count, ppos);
	if (ret >= 0 && ppos)
		io_buff->filp->f_pos = pos;
	return ret;
}

static const struct bpf_func_proto bpf_io_write_proto = {
	.func		= bpf_io_write,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
};

BPF_CALL_3(bpf_io_seek, struct bpf_io_buff *, io_buff, s64, offset, u32, whence)
{
	if (whence <= SEEK_MAX) {
		return generic_file_llseek(io_buff->filp, offset, whence);
	}
	return -EINVAL;
}

static const struct bpf_func_proto bpf_io_seek_proto = {
	.func		= bpf_io_seek,
	.gpl_only	= false,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_ANYTHING,
};

static int bpf_noop_prologue(struct bpf_insn *insn_buf, bool direct_write,
			     const struct bpf_prog *prog)
{
	/* Neither direct read nor direct write requires any preliminary
	 * action.
	 */
	return 0;
}

static const struct bpf_func_proto *
io_func_proto(enum bpf_func_id func_id, const struct bpf_prog *prog)
{
	switch (func_id) {
	case BPF_FUNC_io_read:
		return prog->aux->sleepable ? &bpf_io_read_proto : NULL;
	case BPF_FUNC_io_write:
		return prog->aux->sleepable ? &bpf_io_write_proto : NULL;
	case BPF_FUNC_io_seek:
		return prog->aux->sleepable ? &bpf_io_seek_proto : NULL;
	default:
		return bpf_base_func_proto(func_id);
	}
}

static bool __is_valid_io_access(int off, int size)
{
	if (off < 0 || off >= sizeof(struct bpf_io_md))
		return false;
	if (off % size != 0)
		return false;
	if (size != sizeof(__u32))
		return false;

	return true;
}

static bool io_is_valid_access(int off, int size,
			       enum bpf_access_type type,
			       const struct bpf_prog *prog,
			       struct bpf_insn_access_aux *info)
{
	switch (off) {
	case offsetof(struct bpf_io_md, buf):
		info->reg_type = PTR_TO_PACKET;
		break;
	case offsetof(struct bpf_io_md, buf_end):
		info->reg_type = PTR_TO_PACKET_END;
		break;
	}
	return __is_valid_io_access(off, size);
}

static u32 io_convert_ctx_access(enum bpf_access_type type,
				  const struct bpf_insn *si,
				  struct bpf_insn *insn_buf,
				  struct bpf_prog *prog, u32 *target_size)
{
	struct bpf_insn *insn = insn_buf;
	switch (si->off) {
	case offsetof(struct bpf_io_md, buf):
		*insn++ = BPF_LDX_MEM(BPF_FIELD_SIZEOF(struct bpf_io_buff, buf),
				      si->dst_reg, si->src_reg,
				      offsetof(struct bpf_io_buff, buf));
		break;
	case offsetof(struct bpf_io_md, buf_end):
		*insn++ = BPF_LDX_MEM(BPF_FIELD_SIZEOF(struct bpf_io_buff, buf_end),
				      si->dst_reg, si->src_reg,
				      offsetof(struct bpf_io_buff, buf_end));
		break;
	}
	return insn - insn_buf;
}


const struct bpf_verifier_ops io_verifier_ops = {
	.get_func_proto		= io_func_proto,
	.is_valid_access	= io_is_valid_access,
	.convert_ctx_access	= io_convert_ctx_access,
	.gen_prologue		= bpf_noop_prologue,
};

const struct bpf_prog_ops io_prog_ops = {
	.test_run		= bpf_prog_test_run_io,
};

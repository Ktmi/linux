#ifndef _LINUX_BPF_IO_H
#define _LINUX_BPF_IO_H

#include <linux/file.h>

struct bpf_io_buff {
    void *buf;
    void *buf_end;
    int fd;
    struct file *filp;
};

#endif
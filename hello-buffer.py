#!/usr/bin/python
from bcc import BPF
#nobrainer_ends


#подготовка паровозика
program= r"""

BPF_PERF_OUTPUT(output);

struct data_t {
   int pid;
   int uid;
   char command[16];
   char message[12];
};

int hello(void *ctx) {
   struct data_t data = {};
   char message[12] = "Hello World";
   data.pid = bpf_get_current_pid_tgid() >> 32;
   data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
   bpf_get_current_comm(&data.command, sizeof(data.command));
   bpf_probe_read_kernel(&data.message, sizeof(data.message), message);
   output.perf_submit(ctx, &data, sizeof(data));

   return 0;
}

"""
#паровозик выезжает
b = BPF(text=program)
#прицепляемся к этому системному вызову
syscall = b.get_syscall_fnname("execve")
#прицепляемся в функции hello eBPF программы
b.attach_kprobe(event=syscall, fn_name="hello")

#колбэк
def print_event(cpu, data, size):
   #обратиться к bpfmap подобрать мапу output из паровозика
   data = b["output"].event(data)
   print(f"{data.pid} {data.uid} {data.command.decode()} " + \
   f"{data.message.decode()}")

#открыть буфер и когда читаем из него вызвать колбэк для обработки мапы паровозика
b["output"].open_perf_buffer(print_event)

while True:
   b.perf_buffer_poll()

#!/usr/bin/python
from bcc import BPF
#nobrainer_ends

#История паровозика "Ту-ту". 
#Жил был паровозик. 
#Как-то в один свой день рождения он решил устроить вечеринку и попросить своих друзей пригласить кого-нибудь еще чтобы не было скучно! 
#Паровозик был любознателен с самого детства и он очень хотел знать, как зовут пассажиров, которых он перевозит, а также номера их билетов. 
#Его терзал этот вопрос прямо аж до глубины его паровозной души, до самой топки. 

#У него была подруга - добрая пчёлка. 
#Как только наш Ту-ту вспомнил о неё, то решил позвонил пчёлке, чтобы помочь ему с организацией такого важного праздника.
#Добрая пчёлка согласилась не раздумывая, ведь ей нравился паровозик Ту-ту. 
#Она прилетела и радостно зажжужала: "Не волнуйся паровозик, я помогу тебе и расскажу как зовут пассажиров, что сидят в твоих вагонах, а также номера их билетов, а также контакт друзей от имени которых они приглашены! 

#Пчёлка зажгла так радостно, что паровозик был просто в восторге. В топку бросали дрова всю ночь. Огонь был такой мощный, что его поршни отстукивали мелодии всю ночь на радость и веселье всем гостям!

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

#пчёлкино жужжание (колбэк).
def print_event(cpu, data, size):
   #обратиться к bpfmap собрать мёд для паровозика
   data = b["output"].event(data)
   print(f"{data.pid} {data.uid} {data.command.decode()} " + \
   f"{data.message.decode()}")

#открыть буфер и когда читаем из него каждый раз, пчёлка радостно жужит
b["output"].open_perf_buffer(print_event)

while True:
   b.perf_buffer_poll()

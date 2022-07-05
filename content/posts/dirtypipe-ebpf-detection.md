---
title: "Detecting CVE-2022-0847 exploitation"
date: 2022-07-05T16:00:00+02:00
Summary: This article is about detecting Dirty Pipe exploitation attempts thanks to eBPF.
---

CVE-2022-0847, aka Dirty Pipe, was first reported by Max Kellermann in February
2022. This vulnerability allows to overwrite any read-only file, including
root-owned ones, from any unprivileged user. As you can imagine, the
exploitation of Dirty Pipe is a wide open door to privilege escalation in a
pretty straight forward and clean way… In fact, Dirty Pipe is so clean that it
looks like it was a legitimate feature and that Linux was meant to work that
way. It affects every Linux kernel since the version 5.8 and was fixed in Linux
5.16.11, 5.15.25 and 5.10.102. Max Kellermann wrote a great article about his
discovery on his blog which I strongly recommend if you want to learn more:
[dirtypipe.cm4all.com](https://dirtypipe.cm4all.com/).

So how could we detect exploitation of CVE-2022-0847? 🤔

Dirty Pipe being mostly about the page cache, pipes and splices, we knew we had
to monitor syscalls. We first thought about Auditd, a built-in Linux kernel
feature made to monitor syscalls, file access, and more. Auditd is a nice tool
since you can filter properties such as argument values or permissions. But
would it have been applicable to our case? Well, let's think about it: 🔍

- Could we have hooked *open()*? It's a very common syscall, and the argument
  could have been any file… ➤ No ❌
- Could we have hooked *pipe()*? Hooking a simple *splice()* doesn't make
  sense... ➤ No ❌
- Could we have hooked *write()*? That wouldn't have helped either, writing in a
  file descriptor is completely normal… ➤ No ❌
- Could we have hooked *splice()*? That's interesting! Let's look at *splice()*
  arguments: `splice(int fd_in, off64_t *off_in, int fd_out, off64_t *off_out,
  size_t len, unsigned int flags);`. What does Dirty Pipe do? *fd_in* is a file,
  *fd_out* is a pipe, and *len* is above 0. So first, splicing a file and a pipe
  isn't necessarily something bad. Second, splicing a length above 0 is totally
  normal. Third, a file and a pipe are file descriptors, *fd_in* and *fd_out*
  are integers equal to 3, 4, 5, 6, etc… So we wouldn't even be able to see the
  difference between file descriptors. ➤ No ❌
- Checking if the `PIPE_BUF_FLAG_CAN_MERGE` is set in the page? Don't even think
  about it with Auditd... ➤ No ❌

"it looks like it was a legitimate feature", well this was kind of a problem for
us, how could we detect evil behavior if every single syscall seems legitimate?

Well, Auditd wasn't the solution. We also tried
[SysmonForLinux](https://github.com/Sysinternals/SysmonForLinux), but it was
still pretty new at the time, and wasn't convincing.

And then, a colleague suggested *the* tool. The one that was going to allow us
to detect this filthy exploit: [eBPF](https://ebpf.io/) 🐝.

eBPF is a technology made to execute code between userspace and the kernel. It
supports user probes, kernel probes, but also tracepoints! With that, every
single time a hooked system function is called, the program running at the
kernel/user space level will be in capacity of manipulating it's arguments,
reading structures, checking the return values, etc.

Thanks to eBPF, we could have done syscall correlation, but it would have been
very slow, without mentioning the problem of memory management in order to keep
a trace of all the calls by PID… So we had another idea 💡:

1. Hook the *splice()* syscall
2. Get its *fd_in* and *fd_out*
3. Get as much information as possible thanks to the `bpf_get_current_task()`
   eBPF helper and its `struct task_struct` *(Unlike Auditd, this allowed us to
   check the file descriptors properties)*
4. Check if *fd_in* is a file
5. Check if *fd_out* is a pipe
6. Check if *fd_in* is read-only
7. Check if the last page buf ring has the `PIPE_BUF_FLAG_CAN_MERGE` flag set
   *(Thanks to `struct task_struct` again)*
8. Return the properties

The big part of this detection is the navigation through the `struct
task_struct` in order to get the right information :

![struct task_struct](/images/6c067f59b946346b4a8eaae818c86b4fa76a7c05.jpg)

Technically, if you read Max Kellermann's article, this isn't a way to detect
the CVE-2022-0847 exploitation itself. To do so, we would have needed to hook
the write syscall in order to make a correlation with the *fd_out* (the pipe) in
*splice()* and be sure that the program writes into it, but again, it would have
slowed down your processes. Here, we are able to detect a specific context
before the exploitation. Then, if the program writes into the pipe and the
kernel is vulnerable, it will overwrite the targeted file.

![demo](/images/088d790795eb65a66c268d61039feeea5455bae6.gif)

> Just before releasing our work we found this wonderful article from
> Datadog team!
>
> [Datadog, *"The Dirty Pipe vulnerability: Overview, detection, and
> remediation"*, March 10th
> 2022](https://www.datadoghq.com/blog/dirty-pipe-vulnerability-overview-and-remediation/)

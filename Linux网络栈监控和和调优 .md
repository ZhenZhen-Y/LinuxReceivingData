# Linux网络栈监控调优：接收数据

## Linux网络设备子系统

### 数据来了

#### 数据接收调优

**中断合并**
中断合并会将多个中断事件放到一起，累积到一定阈值后才向 CPU 发起中断请求。
这有助于防止中断风暴、提升吞吐量，但会提高延迟。更少的中断产生会导致更高的吞吐量、更高的延迟和更低的 CPU 使用率，反之则相反。
```igb```，```e1000```以及其它驱动的早期版本，包含了一个叫做```InterruptThrottleRate```的参数，用于中断合并设置。在当前的许多驱动中，该参数已被通用的```ethtool```函数取代

``` shell
$ sudo ethtool -c eth0
Coalesce parameters for eth0:
Adaptive RX: off  TX: off
stats-block-usecs: 0
sample-interval: 0
pkt-rate-low: 0
pkt-rate-high: 0
···
 ```
```ethtool```提供了用于中断合并相关的通用接口，但不是所有的设备或驱动都支持相关设置，需要查看驱动文档或驱动源码来确定哪些支持哪些设置，哪些不支持。ethtool文档中指明，驱动程序未实现接口会被静默忽略。
某些驱动支持一个有趣的选项“自适应RX/TX中断合并”。该选项通常在硬件中实现，驱动程序需要通知网卡启用这个选项。
启用自适应RX/TX中断合并后，会调整中断发送，在接受包的速率较低时可以降低延迟，在接收包速率较高时可以提高吞吐量。
启用自适应RX/TX中断合并的命令：
``` shell
$ sudo ethtool -C eth0 adaptive-rx on
 ```
还可以用```ethtool -C ```设置其它选项，常用的选项有：
- ```rx-usecs```:数据包到达后，RX中断产生的延迟时间（微秒）
- ```rx-frames```:RX中断产生前能接收的最大数据帧数量
- ```rx-usecs-irq```:当主机正在处理中断时，RX中断产生的延迟时间（微妙）
- ```rx-frams-irq```:当系统正在处理中断时，RX中断产生前能接收的最大数据帧数量
注意，用中断合并进行优化时，应该确保网络堆栈的其余部分也得到了优化，仅仅优化中断合并这一项带来的效果有限。

**调整中断的亲和力**
如果网卡支持RSS/多队列或者试图针对数据局部性进行优化，可以指定一组特定的 CPU 来处理网卡产生的中断。
如果确定要调整中断亲和力，首先应该检查是否有在运行```irqbalance```守护进程，这个守护进程会自动将中断均衡的分配的各个CPU，它可能覆盖掉你的设置。如果```irqbalance```在运行，应该禁用```irqbalance```或者将```--banirq```与```IRQBALANCE_BANNED_CPUS ```结合使用，让```irqbalance```不覆盖你做的修改。
接下来，查看```/proc/interrupts```文件获取网卡每个RX队列的中断号列表。
最后，修改每个中断号的```/proc/irq/IRQ_NUMBER/smp_affinity```来指定用于处理该中断的 CPU。
只需向该文件写入一个十六进制的数字，以指示内核应该使用哪个cpu来处理该中断。
``` shell
$ sudo bash -c 'echo 1 > /proc/irq/8/smp_affinity'
 ```
 ### 网络数据处理

 一旦软中断代码判断有软中断线程处于挂起，就会执行```net_rx_action```，网络数据开始处理。
 #### ```net_rx_action```处理循环

 ```net_rx_action```开始处理以DMA形式从网卡送到内存的包，该函数遍历当前CPU队列的NAPI结构体列表，依次出队列，并进行操作。
函数中处理数据while循环限制了NAPI```poll```函数可能消耗的任务量和执行时间，通过以下两种方式：
- 跟踪任务量预算```budget ```（可调整）
- 检查运行时间
代码取自Linux内核代码```net/core/dev.c:```
``` c
  while (!list_empty(&sd->poll_list)) {
    struct napi_struct *n;
    int work, weight;

    /* If softirq window is exhausted then punt.
     * Allow this to run for 2 jiffies since which will allow
     * an average latency of 1.5/HZ.
     */
    if (unlikely(budget <= 0 || time_after_eq(jiffies, time_limit)))
      goto softnet_break;
 ```
 这就是内核防止处理包过程消耗整个CPU的方法。代码中```budget```是指将每个NAPI结构体注册到（registered ）CPU的总可用预算。
 处理来自网卡硬件的硬中断和执行软中断程序的是同一个 CPU，多队列网卡可能出现多个NAPI结构体被注册到同一个CPU上的情况，同一CPU上所有的NAPI结构体共享一份```budget```。
 如果没有足够的CPU分散来自网卡的中断，可增大```net_rx_action``` ```budget```来使每个CPU处理更多的包。增大```budget```会使CPU使用率变大（```top```等命令看到的```sitime```或```si```），但可以减少延迟，因为数据处理的更加迅速。
 注意：无论```budget```如何，CPU仍然会受到2```jiffies```的时间限制
 #### NAPI```poll```函数及权重

 网络驱动程序使用```netif_napi_add```注册```poll```函数，```igb```驱动程序有如下代码：
 ``` c
   /* initialize NAPI */
  netif_napi_add(adapter->netdev, &q_vector->napi, igb_poll, 64);
  ```
  该函数注册了权重为64的NAPI结构体，```net_rx_action```处理循环中有使用到权重：
  ``` c
weight = n->weight;

work = 0;
if (test_bit(NAPI_STATE_SCHED, &n->state)) {
        work = n->poll(n, weight);
        trace_napi_poll(n);
}

WARN_ON_ONCE(work > weight);

budget -= work;
  ```
在该代码中，```n```为```struct NAPI```，获取NAPI的权重（64），并作为入参传给```poll```函数，```poll```函数返回处理的数据帧的数量，```budget```会减去这个值，假设：
- 驱动使用的权重值为64（Linux 3.13.0）
- ```budget```值为默认的300

当出现如下情况时，系统将停止处理数据：
- ```igb_poll```函数调用次数超过五次（如果没有数据处理，该值会更小）
- 时间已经过了至少2个jiffies
#### NAPI与网络硬件驱动之间的约定（contract）

关闭NAPI时NAPI子系统与网络硬件驱动之间的重要约定之一，具体如下：
- 如果驱动的```poll```函数消耗了它所有的权重（64），它就不能修改NAPI的状态，将由```net_rx_action```函数关闭NAPI
- 如果驱动```poll```函数没有消耗完它的权重，则驱动必须关闭NAPI。NPAI将在收到下一个中断以及驱动的中断处理程序调用```napi_schedule```时重新打开。
#### ```net_rx_action```处理循环

```net_rx_action```处理循环的最后一段代码处理前面提到的关闭NAPI，代码节选如下：
``` c
/* Drivers must not modify the NAPI state if they
 * consume the entire weight.  In such cases this code
 * still "owns" the NAPI instance and therefore can
 * move the instance around on the list at-will.
 */
if (unlikely(work == weight)) {
  if (unlikely(napi_disable_pending(n))) {
    local_irq_enable();
    napi_complete(n);
    local_irq_disable();
  } else {
    if (n->gro_list) {
      /* flush too old packets
       * If HZ < 1000, flush all packets.
       */
      local_irq_enable();
      napi_gro_flush(n, HZ >= 1000);
      local_irq_disable();
    }
    list_move_tail(&n->poll_list, &sd->poll_list);
  }
}
 ```
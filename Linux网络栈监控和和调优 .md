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
 如果所有的权重都被使用了，```net_rx_action```会处理两种情况：
 - 网络设备需要关闭（例如用户输入了```ifconfig eth0 down```）
 - 如果设备没有被关闭，检查通用接收卸载（eneric receive offload, GRO）列表。如果时钟tick rate >= 1000，所有最近更新的GRO网络流都会被刷新。将NAPI结构体移到GRO列表的末尾，这样循环的下一次迭代会注册并处理下一个NAPI结构体。
 这就是数据处理循环如何调用驱动的轮询函数处理数据。稍后将看到```poll```函数获取网络数据并将其发送到上层堆栈上进行处理。
#### 到达限制时退出循环

当出现下列情况时，```net_rx_action```循环将会退出
- 当前CPU已经没有已注册的NAPI结构体需要处理（```!list_empty(&sd->poll_list)```）
- 剩余```budget<=0```
- 到达2jiffies的时间限制
代码如下：
``` c
/* If softirq window is exhausted then punt.
 * Allow this to run for 2 jiffies since which will allow
 * an average latency of 1.5/HZ.
 */
if (unlikely(budget <= 0 || time_after_eq(jiffies, time_limit)))
  goto softnet_break;
 ```

``` c
softnet_break:
  sd->time_squeeze++;
  __raise_softirq_irqoff(NET_RX_SOFTIRQ);
  goto out;
 ```
退出时，```struct softnet_data```结构增加了一些统计信息，软中断```NET_RX_SOFTIRQ ```关闭。```time_squeeze```字段的含义是:```net_rx_action```还有数据未处理完，但由于```budget<=0```或到达2jiffies的时间限制而退出的次数。该计数器对于理解网络数据处理的瓶颈十分重要。关闭```NET_RX_SOFTIRQ ```是为了释放CPU资源给其它任务使用，不独占CPU。
接着会执行到了```out```标签所在的代码。另外还有一种条件也会跳转到```out```：所有 NAPI 结构体都已处理完，所有驱动都已经关闭 NAPI ，没有什么工作需要 ```net_rx_action```做了。
在```net_rx_action```return之前，```out```调用了```net_rps_action_and_irq_enable```。如果接收数据包转向（Receive packet steering, RPS）功能打卡，该函数唤醒其它的CPU开始处理数据包
我们后面会看到 RPS 是如何工作的。现在先看看怎样监控```net_rx_action```处理循环的运行状态，以及了解 NAPI ```poll```函数的实现，这样才能更好的理解网络栈。
#### NAPI```poll```函数

驱动程序会分配一段内存用于DMA，将网卡收到的包写到内存。DMA获取到数据后，驱动程序会解除内存映射，获取数据并发送到网络堆栈上。
以```igb```驱动程序为例，了解其如何工作。
**```igb_poll```**
``` c
/**
 *  igb_poll - NAPI Rx polling callback
 *  @napi: napi polling structure
 *  @budget: count of how many packets we should handle
 **/
static int igb_poll(struct napi_struct *napi, int budget)
{
        struct igb_q_vector *q_vector = container_of(napi,
                                                     struct igb_q_vector,
                                                     napi);
        bool clean_complete = true;

#ifdef CONFIG_IGB_DCA
        if (q_vector->adapter->flags & IGB_FLAG_DCA_ENABLED)
                igb_update_dca(q_vector);
#endif

        /* ... */

        if (q_vector->rx.ring)
                clean_complete &= igb_clean_rx_irq(q_vector, budget);

        /* If all work not completed, return budget and keep polling */
        if (!clean_complete)
                return budget;

        /* If not enough Rx work done, exit the polling mode */
        napi_complete(napi);
        igb_ring_irq_enable(q_vector);

        return 0;
}
 ```
该段代码做了以下工作：
- 如果内核支持且启用了直接缓存访问（ Direct Cache Access, DCA），则会CPU缓存进行处理，对RX ring buffer的访问将会达到CPU Cache。
- ```igb_clean_rx_irq```，下文详述
- ```clean_complete```，判断是否还有更多的工作可以完成，如果有，返回```budget```。
- 如果所有的工作都已完成，驱动程序通过调用```napi_complete```来关闭NAPI，并通过调用```igb_ring_irq_enable```来重新启用中断。下一个到达的中断将重新打开NAPI。

**```igb_clean_rx_irq```**
```igb_clean_rx_irq```函数是一个循环，每次处理一个包，直到```budget```用完或没其它数据需要处理。
```igb_clean_rx_irq```函数做了如下工作：
- 当已使用的缓存被释放时，分配新的缓存用于接收数据，每次新增```IGB_RX_BUFFER_WRITE```(16)
- 从RX队列取一个buffer，保存到```skb```结构体中
- 检查该buffer是否为数据包的最后一块buffer，如果是，则到下一步。如果不是，继续从RX队列中取buffer到```skb```结构体中
- 检查数据的layout和头部信息是否正确
- 统计处理的数据量，按```skb->len```增加
- 设置skb结构体的hash、checksum、tiamstam、VLAN id、protocol字段，hash、checksum、tiamstam、VLAN id由硬件提供。protocol字段通过调用```eth_type_trans```函数获得。如果硬件报告校验和（checksum）错误，静态变量```csum_error```会增加。如果校验和正确且为UDP或TCP数据，```skb```结构体会被标记为```CHECKSUM_UNNECESSARY```，。如果校验和错误，将由协议栈处理该包。
- 通过调用```napi_gro_receive```，将```skb```结构体传入网络堆栈
- 更新处理过的包的统计信息
- 继续循环直到处理包的数量达到```budget```
循环结束后，将统计接收包数和字节数信息
在了解网络堆栈前，先看看如何监控和调优网络软中断和GRO(Generic Receive Offloading)。
#### 监控网络数据处理

**```/proc/net/softnet_stat```**

如果 ```budget``` 或 time limit 到了而仍有包需要处理，那```net_rx_action```函数在退出循环之前会更新统计信息，这个统计信息被存储到该CPU的```struct softnet_data```结构体中。
这些统计信息输出到proc的一个文件中：```/proc/net/softnet_stat``` ，但该文件的内容没有标记，且随着不同内核版本有所变化。
可以通过内核源码，查看```/proc/net/softnet_stat```文件中各个字段的含义，在Linux 3.13.0中，在Linux 3.13.0内核源码中，各字段含义如下：
``` c
  seq_printf(seq,
       "%08x %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x\n",
       sd->processed, sd->dropped, sd->time_squeeze, 0,
       0, 0, 0, 0, /* was fastroute */
       sd->cpu_collision, sd->received_rps, flow_limit_count);
 ```
在接下来介绍网络堆栈分析时，会举例说明其中一些字段是何时、在哪里被更新的，例如前面已经看到了```time_squeeze```是在```net_rx_action```中更新的。
```/proc/net/softnet_stat```文件内容结构如下：
``` shell
$ cat /proc/net/softnet_stat
6dcad223 00000000 00000001 00000000 00000000 00000000 00000000 00000000 00000000 00000000
6f0e1565 00000000 00000002 00000000 00000000 00000000 00000000 00000000 00000000 00000000
660774ec 00000000 00000003 00000000 00000000 00000000 00000000 00000000 00000000 00000000
61c99331 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
6794b1b3 00000000 00000005 00000000 00000000 00000000 00000000 00000000 00000000 00000000
6488cb92 00000000 00000001 00000000 00000000 00000000 00000000 00000000 00000000 00000000
 ```
关于```/proc/net/softnet_stat```的细节：
- ```/proc/net/softnet_stat```中每一行代表一个```struct softnet_data```结构体变量，每各CPU有一个该结构体
- 每个值以16进制显示
- 第一列，```sd->processed```，是处理的网络帧的数量。如果进行了多网卡绑定，该值可能超过总的接收网络帧数量。因为多网卡绑定驱动有时会使网络数据被重复处理（re-processed）
- 第二列，```sd->dropped``` ，是由于处理队列上没有空间而导致丢包的数量
- 第三列，```sd->time_squeeze```，```net_rx_action```还有数据未处理完，但由于```budget```或时间限制而退出的次数。增大```budget```大小可以减少这种情况发生。
- 第四到第八列总为0
- 第九列，```sd->cpu_collision```，是发送数据时获取设备锁发生冲突的次数。
- 第十列，```sd->received_rps```，是该CPU被其它CPU唤醒（Inter-processor Interrupt）来处理数据包的次数
- 最后一列，```flow_limit_count```，是到达flow limit的次数，flow limit是RPS的特性
最好查看相应版本的内核源码，来确定各个字段的含义
#### 网络数据处理调优

**调整```net_rx_action```budget**

```net_rx_action```budget表示一个CPU一次轮询（poll）允许的最大收包数量。单次 poll 收包时，所有注册到这个 CPU 的 NAPI 结构体变量收包数量之和不能大于这个阈值，修改方法如下：
``` shell
 $ sudo sysctl -w net.core.netdev_budget=600
 ```
如果要保证重启仍然生效，需要将这个配置写到```/etc/sysctl.conf```。

### GRO(Generic Receive Offloading)

GRO是Large Receive Offloading (LRO)的硬件优化的软件实现。
GRO和LRO主要的思想类似，都是将相似的数据包组合在一起来减少网络堆栈上传递的数据包数量，这有助于减少CPU使用率。例如，一个大文件传输的场景，包的数量非常多，大部分包都是一段文件数据。相比于每次都将小包送到网络栈，可以将收到的小包合并成一个很大的包再送到网络堆栈。这使协议层只需处理一个 header，将可以将包含大量数据的大包送到用户程序。
这种优化方式的缺点是信息丢失。数据包的option和flag会在包合并时丢失。
如果用```tcpdump```抓包看到了很大的包，很可能是系统开启了GRO。
#### 调优：使用```ethtool```调整GRO设置

可以用```ethtool```查看GRO是否启用以及进行设置，使用```ethtool -k```查看GRO设置：
``` shell
$ ethtool -k eth0 | grep generic-receive-offload
generic-receive-offload: on
 ```
用```ethtool -K```开启或关闭GRO
``` shell
$ sudo ethtool -K eth0 gro on
 ```
对于大部分驱动，修改GRO设置会先down再 up对应的网卡，在这个过程中，该网卡上的连接都会中断。

### ```napi_gro_receive```

如果开启了GRO，```napi_gro_receive```将负责处理网络数据，并将数据从堆栈送到协议层，大部分相关逻辑在函数 ```dev_gro_receive```里实现。
#### ```dev_gro_receive```
该函数首先检查是否启用了GRO，如果启用了，则准备执行GRO。如果启用了GRO，一系列GROoffload filters将被遍历，以允许上层的协议栈对正在考虑用于GRO的数据进行操作。协议层以此方式让网络设备层知道，此数据包是否属于当前正在接受的网络流的一部分，而且也可以通过这种方式传递一些协议相关的信息。例如，TCP协议需要判断是否/何时应该对一个合并到其他数据包里的包做ACK应答。
```net/core/dev.c```代码节选如下：
``` c
list_for_each_entry_rcu(ptype, head, list) {
  if (ptype->type != type || !ptype->callbacks.gro_receive)
    continue;

  skb_set_network_header(skb, skb_gro_offset(skb));
  skb_reset_mac_len(skb);
  NAPI_GRO_CB(skb)->same_flow = 0;
  NAPI_GRO_CB(skb)->flush = 0;
  NAPI_GRO_CB(skb)->free = 0;

  pp = ptype->callbacks.gro_receive(&napi->gro_list, skb);
  break;
}
 ```
如果协议层提示该flush GRO数据包了，下一步调用```napi_gro_complete```函数，该函数调用协议层的```gro_complete```回调函数，通过调用```netif_receive_skb```将数据包向上传递到堆栈中。
``` c
if (pp) {
  struct sk_buff *nskb = *pp;

  *pp = nskb->next;
  nskb->next = NULL;
  napi_gro_complete(nskb);
  napi->gro_count--;
}
 ``` 
 接下来，如果协议层将该数据包合并到现有流中，则```napi_gro_receive```直接return，因为无其它事可做。
如果未合并数据包，并且系统上的GRO流数量少于```MAX_GRO_SKBS```（默认为8），则添加一个新条目到此CPU的NAPI结构体的```gro_list```中。
``` c
if (NAPI_GRO_CB(skb)->flush || napi->gro_count >= MAX_GRO_SKBS)
  goto normal;

napi->gro_count++;
NAPI_GRO_CB(skb)->count = 1;
NAPI_GRO_CB(skb)->age = jiffies;
skb_shinfo(skb)->gso_size = skb_gro_len(skb);
skb->next = napi->gro_list;
napi->gro_list = skb;
ret = GRO_HELD;
 ```
 ### ```napi_skb_finish```

一旦```dev_gro_receive```完成，将调用```napi_skb_finish```，它释放由于合并数据包而不需要的数据结构，或者调用```netif_receive_skb```将数据向上传递到网络堆栈（如果已经有```MAX_GRO_SKBS```个流被合并了）。
接下来，是时候查看```netif_receive_skb```如何将数据传递到协议层了。 在进行检查之前，我们需要先了解RPS(Receive Packet Steering)。
## Receive Packet Steering(RPS)


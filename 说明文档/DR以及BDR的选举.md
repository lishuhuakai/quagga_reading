最近翻了一下网上关于DR以及BDR选举的文章,发现很多文章的描述都存在问题,而且很多东西都没有描述清楚,所以,我自己打算写一篇文章,将事情彻底讲清楚.

# 参考
最权威的参考资料还是RFC文档,网上大部分文章都不靠谱,甚至TCP/IP路由卷一,都没有讲清楚.有兴趣的同学可以翻一下RFC2328,我这里干脆引用一下得了.
> This section describes the algorithm used for calculating a network’s Designated Router and Backup Designated Router. This algorithm is invoked by the Interface state machine. The initial time a router runs the election algorithm for a network,
the network’s Designated Router and Backup Designated Router are initialized to 0.0.0.0. This indicates the lack of both a Designated Router and a Backup Designated Router.
>The Designated Router election algorithm proceeds as follows:
Call the router doing the calculation Router X. The list of neighbors attached to the network and having established bidirectional communication with Router X is examined. This list is precisely the collection of Router X’s neighbors (on this network) whose state is greater than or equal to 2-Way . Router X itself is also considered to be on the list. Discard all routers from the list that are ineligible to
become Designated Router. (Routers having Router Priority of 0 are ineligible to become Designated Router.) The following steps are then executed, considering only those routers that remain on the list:
(1) Note the current values for the network’s Designated Router
and Backup Designated Router. This is used later for comparison purposes.
(2) Calculate the new Backup Designated Router for the network as follows. Only those routers on the list that have not declared themselves to be Designated Router are eligible to become Backup Designated Router. If one or more of these routers have declared themselves Backup Designated Router (i.e., they are currently listing themselves as Backup Designated Router, but not as Designated Router, in their
Hello Packets) the one having highest Router Priority is declared to be Backup Designated Router. In case of a tie, the one having the highest Router ID is chosen. If no routers have declared themselves Backup Designated Router, Moy Standards Track [Page 75]RFC 2328 OSPF Version 2 April 1998 choose the router having highest Router Priority, (again excluding those routers who have declared themselves Designated Router), and again use the Router ID to break ties.
(3) Calculate the new Designated Router for the network as follows. If one or more of the routers have declared themselves Designated Router (i.e., they are currently
listing themselves as Designated Router in their Hello Packets) the one having highest Router Priority is declared to be Designated Router. In case of a tie, the one having the highest Router ID is chosen. If no routers have declared themselves Designated Router, assign the Designated Router to be the same as the newly elected Backup Designated Router.
(4) If Router X is now newly the Designated Router or newly the Backup Designated Router, or is now no longer the Designated Router or no longer the Backup Designated Router, repeat steps 2 and 3, and then proceed to step 5. For example, if Router X is now the Designated Router, when step 2 is repeated X will no longer be eligible for Backup Designated Router election. Among other things, this will ensure that no router will declare itself both Backup Designated Router
and Designated Router.
(5) As a result of these calculations, the router itself may now be Designated Router or Backup Designated Router. See Sections 7.3 and 7.4 for the additional duties this would entail. The router’s interface state should be set accordingly. If the router itself is now Designated Router, the new interface state is DR. If the router itself is now Backup Designated Router, the new interface state is Backup.
Otherwise, the new interface state is DR Other.
(6) If the attached network is an NBMA network, and the router itself has just become either Designated Router or Backup Designated Router, it must start sending Hello Packets to those neighbors that are not eligible to become Designated Router (see Section 9.5.1). This is done by invoking the neighbor event Start for each neighbor having a Router Priority of 0.
(7) If the above calculations have caused the identity of either the Designated Router or Backup Designated Router to change,the set of adjacencies associated with this interface will need to be modified. Some adjacencies may need to be
formed, and others may need to be broken. To accomplish this, invoke the event AdjOK? on all neighbors whose state is at least 2-Way. This will cause their eligibility for adjacency to be reexamined (see Sections 10.3 and 10.4).
The reason behind the election algorithm’s complexity is the desire for an orderly transition from Backup Designated Router to Designated Router, when the current Designated Router fails. 
This orderly transition is ensured through the introduction of hysteresis: no new Backup Designated Router can be chosen until the old Backup accepts its new Designated Router responsibilities.
The above procedure may elect the same router to be both Designated Router and Backup Designated Router, although that router will never be the calculating router (Router X) itself.
The elected Designated Router may not be the router having the highest Router Priority, nor will the Backup Designated Router necessarily have the second highest Router Priority. If Router X is not itself eligible to become Designated Router, it is
possible that neither a Backup Designated Router nor a Designated Router will be selected in the above procedure. Note also that if Router X is the only attached router that is eligible to become Designated Router, it will select itself as Designated Router and there will be no Backup Designated Router for the network.

# 算法
以下算法基本是上面内容的翻译.
一台ospf接口起来的时候,它默认的dr以及bdr都是0.0.0.0,这意味着,这个时候,此接口认为还网络中不存在DR以及BDR.

接下来开始DR的选举算法,假定我们有一台路由器X,它正在运行DR选举算法,它首先会开始检查同一网段上,和X建立了双向连接关系的邻居(邻居状态大于等于two-way),当然,X自己也在这些邻居之中,去掉那些优先级为0的邻居(优先级为0,表示其并不想参与选举),去掉那些Router ID为0的邻居,将其余的邻居加入候选列表.

(1)  先将当前路由器认为的DR以及BDR的值记录下来,这个将由于后面的比较;

(2) 首先选举新的BDR,首先选择BDR的候选者,那些宣称自己为DR的邻居不能作为BDR,如果有1个或者多个候选候选邻居宣称自己为BDR(没有宣称自己为DR),那么它们之中,优先级最高的邻居作为BDR,如果优先级一致,Router ID大的将成为BDR.如果没有邻居宣称自己为BDR, 那就挑选一个拥有最高优先级的作为BDR,优先级一致的话,router-id大的成为BDR(同样的,要排除那些宣称自己为DR的邻居);

(3) 接下来选举DR,流程如下,如果有一个或多个候选邻居宣称自己为DR(也就是说,Hello包中,它们将自己的Router ID填入了DR字段),拥有最高优先级的邻居成为DR,如果优先级一致,则比较Router ID,Router ID大的邻居成为DR,如果没有邻居宣称自己为DR,那么前面选举的BDR成为DR;

(4) 使用(1)中保存的值,如果X成为了新的DR/BDR(之前不是),或者现在已经不是DR/BDR(原来是),重复算法(2),(3)步,然后执行第(5)步.为什么要这么做呢?很简单,经历(2),(3)之后,X现在可能即是DR也是BDR,重新执行之后,我们可以保证,X只有一个角色;

(5) ... (接下来就不是选举算法部分了,省略)

# 问题
## 为什么DR以及BDR一般只要不挂,就不会改变?
假定一个局域网,已经存在了一个DR以及一个BDR,现在另外一台优先级更高的路由器R3加入:
```shell
R1[DR]-------R2[BDR]
          |
	     R3
```
需要说明一下,真实环境收包发包时序可能并非如此,这里仅仅只是为了演示而已.
1) 首先,R3刚起来,认为DR以及BDR为0,开始发送Hello包,DR为0,BDR为0;
2) 接下来R2接收到了R1的Hello包,里面DR为R1, BDR为R2, 以及受到了R2发来的Hello包,里面DR为R1, BDR为R2;
3) R2开始运行选举算法,先选举BDR, BDR只有R2一个候选者,R2成为BDR;
4) 开始选举DR,DR只有R1这一个候选者,因此,R1为DR.
## 继续上面的拓扑,如果R1挂掉了呢?
```shell
R1[DR]-X------R2[BDR]
          |
	     R3
```
等待一段时间,R2和R3没有收到R1的Hello报文,就会将R1从邻居列表中移除.然后重新开始选举.假定这个时候R3将R1移除,但是还没有收到R2的Hello报文.
1) 首先选举BDR,因为R2宣称自己为BDR,选举R2为BDR;
2) 开始选举DR,因为没有邻居宣称自己为DR,那么R2成为DR;
3) 因为R3一直都是DROther,因此就不执行算法步骤(2)和(3);

R2同样也会执行选举:
1) 首先选举BDR,因为R2宣称自己为BDR,选举R2为BDR;
2) 开始选举DR,因为没有邻居宣称自己为DR,那么R2成为DR;
3) R2成为了DR,重新执行算法步骤(2)和(3);
4) 首先,因为R2成为了DR,它不会再成为BDR,因此BDR为R3;
5) R2经过DR选举仍然是DR.

接着R2和R3会互相洪泛Hello报文,R3收到R2的Hello报文后,会再次进行选举:
1) 首先选举BDR,因为R2为DR,因此R3成为了BDR;
2) R2仍然是DR;
3) 因为R3新成为了BDR,重新执行算法步骤(2)和(3);
4) 选举BDR,R3为BDR;
5) 选举DR,R2为DR;
最终R2和R3会达成一致.
## 什么时候会进行选举过程?
1.新增two-way及以上的邻居;
2.two-way及以上的邻居减少;
3.two-way及以上的邻居宣称自己为DR/BDR (原来不是);
4.two-way及以上的邻居不再宣称自己为DR/BDR (原来是);
5.two-way及以上的邻居的优先级发生变化.



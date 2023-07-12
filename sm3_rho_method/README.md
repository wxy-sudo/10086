# implement the Rho method of reduced SM3

## 实现思路

考虑数列 $\lbrace H_n\rbrace$，其中 $H_0=seed,\ H_{n+1}=hash(H_n)$，易知该数列最终一定会进入一个循环，且数列进入循环前的最后一个值与该循环周期的最后一个值能够发生碰撞。设此循环的周期为 $\rho$，求出该 $\rho$ 的值，然后，令变量 $i$ 和 $j$ 分别从 $H_0$ 和 $H_\rho$ 出发同步迭代，并逐次比较 $i$ 和 $j$ 的值，当判断出二者第一次相等时，即找到了碰撞发生的位置。其中，求 $\rho$ 值可通过如下算法实现：

![Image text](https://github.com/wxy-sudo/wxy-s/blob/main/%E5%88%9B%E6%96%B0%E5%88%9B%E4%B8%9A%E5%9B%BE%E7%89%87/Project2/huan.png)

采用 $Rho$  $method$对 $SM3$寻找碰撞，我们先选取一个随机的 $seed$作为起始值，随后每次分别对消息进行一次 $SM3$和两次 $SM3$，直到找出一组碰撞

```
    EVP_Digest(data, 32, out1, &out1_size, EVP_sm3(), NULL);
    EVP_Digest(out1, 32, out2, &out2_size, EVP_sm3(), NULL);
    while(1) {
        EVP_Digest(out1, 32, out3, &out1_size, EVP_sm3(), NULL);
        EVP_Digest(out2, 32, out2, &out2_size, EVP_sm3(), NULL);
        EVP_Digest(out2, 32, out4, &out2_size, EVP_sm3(), NULL);
        uint32_t key1 = 0;
        std::memcpy(&key1, out3, COLLISION_BYTE);
        

        uint32_t key2 = 0;
        std::memcpy(&key2, out4, COLLISION_BYTE);

        if (key1 == key2) {
            printf("找到碰撞！！！\n");
            printf("第一段消息为：");
            printf_hex(out1, 32);
            printf("\n");
            printf("第一段消息哈希值为：");
            printf_hex(out3, 32);
            printf("\n");

            printf("第二段消息为：");
            printf_hex(out2, 32);
            printf("\n");
            printf("第二段消息哈希值为：");
            printf_hex(out4, 32);
            printf("\n");
            break;

        }
```

优化思路：令变量 $i$ 在数列中迭代：第一轮迭代 $1$ 次得到 $H_1$，将其与 $H_0$ 比较；第二轮迭代 $2$ 次得到 $H_2$ 和 $H_3$，依次与 $H_1$ 比较；第三轮迭代 $4$ 次得到 $H_4$, $H_5$, $H_6$ 和 $H_7$，依次与 $H_3$ 比较……如是重复，每轮迭代 $2^{n-1}$ 次，并依次与上一轮最后一次迭代得到的值比较，直到比较出相同为止，此时 $i$ 在当前轮中迭代的次数即为 $\rho$. 经测试，该算法比原始 Rho Method 通过两变量一快一慢遍历数列求 $\rho$ 值的效率更高，用该算法最终找到一组碰撞的平均总耗时约能达到原方法的 $0.6$ 倍。

## 实现结果

### 24bit

![Image text](https://github.com/wxy-sudo/wxy-s/blob/main/%E5%88%9B%E6%96%B0%E5%88%9B%E4%B8%9A%E5%9B%BE%E7%89%87/Project2/24bit.png)

### 48bit

![Image text](https://github.com/wxy-sudo/wxy-s/blob/main/%E5%88%9B%E6%96%B0%E5%88%9B%E4%B8%9A%E5%9B%BE%E7%89%87/Project2/48bit.png)


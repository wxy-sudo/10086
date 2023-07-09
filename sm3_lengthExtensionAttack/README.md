# implement length extension attack for SM3, SHA256, etc.

这里实现MAC的密钥我们每次选取随机值，因此首先生成随机数生成器

```
std::random_device rd;
std::mt19937 gen(rd());
std::uniform_int_distribution<> dis(0, 255);
```

随后生成随机的密钥

```
uint8_t* key = new uint8_t[64];
for (int i = 0; i < 64; i++) {
  key[i] = static_cast<uint8_t>(dis(gen));
}
```

接着利用已知的key和message实现MAC

```
sm3_update(&sig_ctx, key, 64, data, times);
sig_ctx.nblocks = 0;
sm3_update(&sig_ctx, message, sizeof(message)-1, data, times);
sm3_final(&sig_ctx, digest, data, times);
```

接着对扩展的消息再执行一次MAC计算，并且由于上一次填充了足够的消息，SM3压缩的缓冲区内此时为空，因此将ctx.num设为0

```
uint8_t appended_message[] = "appended! ";
sig_ctx.num = 0;
sig_ctx.nblocks += 1;
sm3_update(&sig_ctx, appended_message, sizeof(appended_message)-1, data, times);
sm3_final(&sig_ctx, digest, data, times);
```

接着对长度扩展后的消息直接进行MAC，与长度扩展攻击得到的MAC进行比较

```
sm3_ctx sig_ctx1;
sm3_init(&sig_ctx1);
sm3_update(&sig_ctx1, pdata, 128 + sizeof(appended_message)-1, message, times);
sig_ctx1.nblocks -= 1; //key不能算在nblocks中，所以要减1
sm3_final(&sig_ctx1, digest2, message, times);
```

实现结果如下图：

![Image text](https://github.com/wxy-sudo/wxy-s/blob/main/%E5%88%9B%E6%96%B0%E5%88%9B%E4%B8%9A%E5%9B%BE%E7%89%87/Project3/%E9%95%BF%E5%BA%A6%E6%89%A9%E5%B1%95%E6%94%BB%E5%87%BB.png)

经过比较发现，长度扩展攻击获得的MAC和直接对消息进行MAC的值一致，因此长度扩展攻击成功！

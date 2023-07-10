# implement the Rho method of reduced SM3

## 实现思路

采用Rho method对SM3寻找碰撞，我们先选取一个随机的data作为起始值，随后每次分别对消息进行一次SM3和两次SM3，知道找出一组碰撞

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

## 实现结果

### 24bit

![Image text](https://github.com/wxy-sudo/wxy-s/blob/main/%E5%88%9B%E6%96%B0%E5%88%9B%E4%B8%9A%E5%9B%BE%E7%89%87/Project2/24bit.png)

### 48bit

![Image text](https://github.com/wxy-sudo/wxy-s/blob/main/%E5%88%9B%E6%96%B0%E5%88%9B%E4%B8%9A%E5%9B%BE%E7%89%87/Project2/48bit.png)


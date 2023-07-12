# Implement the above ECMH scheme

## 实现思路

 $ECMH$的基本要求：
- 同态或递增的多集散列函数
-  $hash({a}) + hash({b}) = hash({a,b})$
- 一个空集映射到EC的无穷大点O
- 多集合中元素的顺序并不重要
- 重复的元素是可能的，{a}和{a，a}有不同的摘要。
- 要更新一个多集的摘要，只需要计算差值。
- 可以在任何椭圆曲线上构建
- 抗碰撞性依赖于ECDLP的困难程度
- 与SM2/ECDSA签名/验证的安全假设相同
- 收益：快速的节点同步，不需要从头做起



- ``ech``函数对单独的消息m进行哈希
```
def ech(u):
    h = int(hashlib.sha256(str(u).encode()).hexdigest(), 16)
    for i in range(0, p):
        x = (h + i) % p
        d = (x ** 3 + a * x + b) % p
        if pow(d, (p - 1) // 2, p) % p == 1:
            y = modular_sqrt(d, p)
            return [x, y]
    return None
```

- ``echs``函数则对一个集合中的消息m进行哈希后，将他们以椭圆曲线加法加在一起
```
def echs(s):
    for x in s:
        point = ech(x)
        if point is not None:
            result[0],result[1] = add(result[0],result[1],point[0],point[1])
    return result
```

## 实现结果

![Image text](https://github.com/wxy-sudo/wxy-s/blob/main/%E5%88%9B%E6%96%B0%E5%88%9B%E4%B8%9A%E5%9B%BE%E7%89%87/Project13/ECMH.png)


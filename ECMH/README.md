# Implement the above ECMH scheme

## 实现思路

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

```

## 实现结果

![Image text](https://github.com/wxy-sudo/wxy-s/blob/main/%E5%88%9B%E6%96%B0%E5%88%9B%E4%B8%9A%E5%9B%BE%E7%89%87/Project13/ECMH.png)


# Impl Merkle Tree following RFC6962

## 实现思路

创建 `MerkleTree` 类，通过递归实现其创建和遍历，验证某一元素是否存在时，先通过遍历找到其对应的叶子节点，若未找到则证明不存在，否则依次验证该叶子节点每个父节点是否正确，如果全部正确则证明存在，否则返回异常。

## 实现结果

![Image text](https://github.com/wxy-sudo/wxy-s/blob/main/%E5%88%9B%E6%96%B0%E5%88%9B%E4%B8%9A%E5%9B%BE%E7%89%87/Project5/Merkle%20Tree.png)

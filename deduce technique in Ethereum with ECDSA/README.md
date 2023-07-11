# report on the application of this deduce technique in Ethereum with ECDSA

## ECDSA

### $KeyGen$:
- $P=d G, n$ is order

### $Sign(\mathrm{M})$ :
- ${Sign}(m)$
- $k \leftarrow Z_n^*, R=k G$
- $r=R_x \bmod n, r \neq 0$
- $e={hash}(m)$
- $s=k^{-1}(e+d r) \bmod n$

### $Verify(\mathrm{r,s})$ of m with P :
- $e={hash}(m)$
- $w=s^{-1} \bmod n$
- $\left(r^{\prime}, s^{\prime}\right)=e \cdot w G+r \cdot w P$
- Check if $r^{\prime}==r$
- Holds for correct sig since
- $e s^{-1} G+r s^{-1} P=s^{-1}(e G+r P)=$
- $k(e+d r)^{-1}(e+d r) G=k G=R$


## Public Key Recovery

- $e s^{-1} G+r s^{-1} P=s^{-1}(e G+r P)$
- $P=dG=(R-e s^{-1})s r^{-1}$
  
How to compute $P$

- $e={hash}(m)$
- $s=k^{-1}(e+d r) \bmod n$

在使用Ethereum的过程中，每次需要使用ECDSA进行签名时，发送方可以不必向验证方发送自己的公钥，而是由验证方根据消息等已知信息自行求出发送方的公钥

通过这种方法，可以减少发送方发送公钥消耗的带宽，增加传输效率

little tips：由于验证方仅可获得r，也就是R的横坐标，而一个横坐标可以对应两个纵坐标，同时根据这两个纵坐标，每个纵坐标可以恢复出两个P的横坐标，最终至多可以获得4个公钥，而其中有且仅有一个公钥是发送方真正使用的公钥，因此发送方可能需要通过添加冗余信息的方法使验证方能够判断出哪个是正确的公钥。

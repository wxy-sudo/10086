# report on the application of this deduce technique in Ethereum with ECDSA

## ECDSA

### $Precompute$:
- compute $Z_A=H_{256}\left(E N T L_A\left\|I D_A\right\| a\|b\| x_G\left\|y_G\right\| x_A \| y_A\right)$
- identifier $I D_A$ length is entlen $A_A$
- $E N T L_A$ is encoded from entlen ${ }_A$ and takes two bytes
- $\mathrm{H}_{256}$ : hash function SM3
### $KeyGen$:
- $P_A=d_A \cdot G=\left(x_A, y_A\right)$
### $Sign(\mathrm{M})$ :
- $\{Sign}_{d_A}\left(M, Z_A\right) \rightarrow(r, s)$
- $\{Set} \pi=Z_A|| M$
- Compute $e=H_v(\bar{M})$, where the output of $H_v$ is $v$
- Generate random number $k \in[1, n-1]$
- Compute $k G=\left(x_1, y_1\right)$
- Compute $r=\left(e+x_1\right) \bmod n$,
- if $r=0$ or $r+k=n$, generate random number $k$ again
- Compute $s=\left(\left(1+d_A\right)^{-1} \cdot\left(k-r \cdot d_A\right)\right) \bmod n$
- if $s=0$, generate random number $k$ again

## Public Key Recovery

- $s=\left(\left(1+d_A\right)^{-1} \cdot\left(k-r \cdot d_A\right)\right) \bmod n$
- $s \cdot\left(1+d_A\right)=\left(k-r \cdot d_A\right) \bmod n$
- $(s+r) d_A=(k-s) \bmod n$
- $(s+r) d_A G=(k-s) G \bmod n$
- $d_A \cdot G=P_A=(s+r)^{-1}(k G-s G)$
  
How to compute $k G$

- $(k G)_x=x_1=(r-e) \bmod n$, then compute $y_1$
- $e={Hash}\left(Z_A \| M\right)$ where $Z_A$ is not related public key

在使用Ethereum的过程中，每次需要使用ECDSA进行签名时，发送方可以不必向验证方发送自己的公钥，而是由验证方根据消息等已知信息自行求出发送方的公钥

通过这种方法，可以减少发送方发送公钥消耗的带宽，增加传输效率

little tips：对于一个ECDSA签名，验证方可能恢复出多个公钥，其中包括一些错误的公钥，发送方可以通过添加冗余信息是验证方能够判断出正确的公钥。

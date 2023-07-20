import sage

F = GF (0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F)  #生成一个给定阶数的全局唯一有限域
C = EllipticCurve ([F (0), F (7)])     #构造出椭圆曲线


G = C.lift_x(0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798)
N = GF (C.order())
P = P=-C.lift_x(0x11db93e1dcdb8a016b49840f8c53bc1eb68a382e97b1482ecad7b148a6909a5c) # block 9 coinbase payout key.

def forge(c, a=-1):  # Create a forged 'ECDSA'  (hashless) signature
  a = N(a)
  R = c*G + int(a)*P
  s = N(int(R.xy()[0]))/a
  m = N(c)*N(int(R.xy()[0]))/a
  print ('hash1 = %d'%m)
  print ('r1 = %d'%(int(R.xy()[0])))
  print ('s1 = %d'%s)

forge(1)
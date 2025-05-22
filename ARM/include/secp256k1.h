#ifndef SECP256K1H
#define SECP256K1H

#include "Point.h"
#include "Int.h"
#include <vector>

class Secp256K1 {

public:
  Secp256K1();
  ~Secp256K1();
  void Init();
  Point NextKey(Point &key);
  void Check();
  bool  EC(Point &p);
  // Affine + Affine
  Point AddAffine(Point &p1, Point &p2);
  // Jacobian + Affine
  Point AddMixed(Point &p1, Point &p2);
  // Jacobian + Jacobian
  Point AddJacobian(Point &p1, Point &p2);
  // Affine + Affine
  Point DoubleAffine(Point &p);
  // Jacobian + Jacobian
  Point DoubleJacobian(Point &p);
  uint8_t GetByte(std::string &str,int idx);
  Int GetY(Int x, bool isEven);
  Point GTable[256*32];       
  Point G;
  Int   order;
  Point ComputePublicKey(Int *privKey, bool reduce);
  std::vector<Point> BatchComputePublicKeys(Secp256K1 *s,
                                         std::vector<Int> &privKeys);
};

#endif // SECP256K1H

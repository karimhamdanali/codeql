/**
 * @name Insecure randomness
 * @description When a non-cryptographic PRNG is used in a cryptographic context, it can expose the cryptography to certain types of attacks.
 * @kind problem
 * @problem.severity error
 * @security-severity 7.8
 * @precision medium
 * @id swift/insecure-randomness
 * @tags security
 *       external/cwe/cwe-338
 */

import swift

from ApplyExpr call, AbstractFunctionDecl func, string name
where
  call.getStaticTarget() = func and
  func.getModule().getName() = ["SwiftGlibc", "Darwin"] and
  name = func.getName() and
  name =
    [
      "rand()", "rand_r(_:)", "random()", "random_r(_:_:)", "drand48()", "erand48(_:)", "lrand48()",
      "nrand48(_:)", "mrand48()", "jrand48(_:)",
    ]
select call, "Use of cryptographically weak RNG " + name

#if os(Linux)
import Glibc
#else
import Darwin
#endif

func generateSessionID() -> Int32 {
	srand(time())  // BAD: Predictable Seed in PRNG (CWE-337)
	return rand()  // BAD: Use of Cryptographically Weak Pseudo-Random Number Generator (CWE-338)
}

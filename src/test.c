#include <stdio.h>
#include <sodium.h>
/* Plan to fix password hashing:
   1. Retrieve key from user
   2. Randomly generate master key.
   3. Put randomly generated salt somewhere. It does not have to be
      kept secret.
   4. Generate encryption key from master key 
   5. Generate hashing key from master key. (different salts)
   6. Use those keys instead.
*/
int main() {
  if (sodium_init() == -1) {
    printf("Sodium library could not be initialized\n");
    return EXIT_FAILURE;
  }

  printf("%d\n", crypto_pwhash_BYTES_MAX);
  return EXIT_SUCCESS;
}

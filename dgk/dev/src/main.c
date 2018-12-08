#include "dgk.h"

int main() {

	srand(time(NULL));
	mpz_t m, c;
	mpz_inits(m,c,NULL);
	mpz_set_ui(m,0);

	unsigned int m2 = 45 ;

	dgk_pk * publicKey=dgk_pk_init();
	dgk_sk * secretKey=dgk_sk_init();
	dgk_key_generation(publicKey,secretKey);
	mpz_t * decrypt_table=calloc(publicKey->u,sizeof(mpz_t));
	for (int i=0;i<publicKey->u;i++) mpz_init(decrypt_table[i]);
	dgk_encrypt_mpz(c,m,publicKey);
	printf("%d\n",dgk_is_0_encryption(c,secretKey));
	dgk_precom_decrypt(decrypt_table,publicKey,secretKey);
	dgk_encrypt_ui(c,m2,publicKey);
	dgk_decrypt(m,c,decrypt_table,publicKey,secretKey);
	gmp_printf("test : %Zu \n",m);

  for (int i=0;i<publicKey->u;i++) mpz_clear(decrypt_table[i]);
  free(decrypt_table);
  mpz_clears(m,c,NULL);
  dgk_pk_clear(publicKey);
  dgk_sk_clear(secretKey);

}

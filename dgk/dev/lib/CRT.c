void mpz_CRT(mpz_t x, mpz_t * cong, mpz_t * moduli, int nb_eq) {

	int mod=1;
	mpz_t N, N_i, d_i;
	mpz_inits(N,N_i,d_i,NULL);
	mpz_set_ui(N,1);
	for (int i=0 ; i<nb_eq ; i++) mpz_mul(N,N,moduli[i]);
	for (int i=0 ; i<nb_eq ; i++) {
		mpz_divexact(N_i,N,moduli[i]);
		mpz_invert(d_i,N_i,moduli[i]);
		mpz_mul(d_i,d_i,N_i);
		mpz_mul(d_i,d_i,cong[i]);
		mpz_add(x,x,d_i);
	}
	mpz_mod(x,x,N);

}

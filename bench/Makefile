CARGS = -std=c99 ../src/hcs_rand.c ../src/com/util.c ../src/com/parson.c -lgmp

all:

s_pcs_encrypt:
	gcc $(CARGS) pcs_encrypt.c ../src/pcs.c

p_pcs_encrypt:
	gcc $(CARGS) pcs_encrypt.c ../src/pcs.c -fopenmp

s_pcs_decrypt:
	gcc $(CARGS) pcs_decrypt.c ../src/pcs.c

p_pcs_decrypt:
	gcc $(CARGS) pcs_decrypt.c ../src/pcs.c -fopenmp

s_egcs_ee_mul:
	gcc $(CARGS) pcs_decrypt.c ../src/egcs.c

p_egcs_ee_mul:
	gcc $(CARGS) pcs_decrypt.c ../src/egcs.c -fopenmp

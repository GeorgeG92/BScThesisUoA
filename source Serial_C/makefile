#nvcc -o test_encrypt_cu test/test_encrypt.cu src/oaes_lib.c src/oaes_base64.cu src/isaac/rand.c cuda_encrypt.cu
all: 
	gcc -o test_encrypt test/test_encrypt.c src/oaes_lib.c src/oaes_base64.c src/isaac/rand.c -w
	gcc -o test_performance test/test_performance.c src/oaes_lib.c src/oaes_base64.c src/isaac/rand.c -w

all:
	nvcc --gpu-architecture=sm_20 -o test_encrypt test/test_encrypt.cu src/oaes_base64.cu cuda/cuda_encrypt.cu src/oaes_lib.c src/isaac/rand.c --maxrregcount=32 -w
	nvcc --gpu-architecture=sm_20 -o test_performance test/test_performance.cu src/oaes_base64.cu cuda/cuda_encrypt.cu src/oaes_lib.c src/isaac/rand.c --maxrregcount=32 -w
__global__ void cuda_oaes_encrypt_block(size_t c_c_len, uint8_t *c_c, uint8_t c_OAES_BLOCK_SIZE, size_t c_m_len, uint8_t c_OAES_OPTION_CBC, OAES_RET *c_rc, oaes_ctx *c_ctx, int c_threadno, oaes_key **key_2, int critical)
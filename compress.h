#include <linux/crypto.h>

void deflate_compress(const char *input,
                      unsigned int input_len,
                      char *output,
                      unsigned int *output_len);
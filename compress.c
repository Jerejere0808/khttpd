#include "compress.h"

void deflate_compress(const char *input,
                      unsigned int input_len,
                      char *output,
                      unsigned int *output_len)
{
    struct crypto_comp *comp;
    struct comp_request *req;

    comp = crypto_alloc_comp("deflate", 0, 0);
    if (IS_ERR(comp)) {
        pr_err("Failed to allocate compression object\n");
        return;
    }

    int ret = crypto_comp_compress(comp, input, input_len, output, output_len);

    if (ret) {
        pr_err("Compression failed with error code: %d\n", ret);
        crypto_free_comp(comp);
        return;
    }

    crypto_free_comp(comp);
    return;
}

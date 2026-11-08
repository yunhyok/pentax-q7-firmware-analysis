#include <stdint.h>

/* Reconstructed Q7 Q13 matrix operation. The output holds raw halfword bits. */
void q7_matrix_mul_q13(uint16_t out[9], const int16_t left[9], const int16_t right[9])
{
    uint16_t result[9];

    for (unsigned row = 0; row < 3; ++row) {
        for (unsigned col = 0; col < 3; ++col) {
            uint32_t acc = UINT32_C(0x1000);

            for (unsigned k = 0; k < 3; ++k) {
                int32_t product = (int32_t)left[3 * row + k] * right[3 * k + col];
                acc += (uint32_t)product;
            }
            result[3 * row + col] = (uint16_t)(acc >> 13);
        }
    }

    /* Finish reading both inputs before the first output store, including overlap. */
    for (unsigned i = 0; i < 9; ++i)
        out[i] = result[i];
}

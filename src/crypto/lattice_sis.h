#pragma once
#include <vector>
#include <stdint.h>

namespace lattice {

struct SISParams {
    uint32_t n, m, q, w;
};

struct SISInstance {
    // A: n x m row-major, values in [0,q)
    std::vector<uint16_t> A;
    // b: n entries in [0,q)
    std::vector<uint16_t> b;
};

// Deterministically derive (A,b) from seed (seed can be header hash bytes)
void DeriveInstance(const unsigned char* seed, size_t seedlen,
                    const SISParams& sp, SISInstance& out);

// Decode x from 2-bit-per-entry packed vector (00->0,01->+1,11->-1,10->invalid)
bool DecodeTernary(const std::vector<unsigned char>& vch, uint32_t m, std::vector<int8_t>& x);

// Verify A * x = b (mod q) and Hamming weight <= w
bool VerifySIS(const SISInstance& I, const SISParams& sp, const std::vector<int8_t>& x);

} // namespace lattice

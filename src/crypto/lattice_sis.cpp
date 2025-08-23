#include "crypto/lattice_sis.h"
#include "hash.h" // CSHA256
#include <string.h>
#include <algorithm>

namespace lattice {

static void sha256_ctr_xof(const unsigned char* seed, size_t seedlen,
                           uint64_t ctr, unsigned char out32[32]) {
    CSHA256 hasher;
    hasher.Write(seed, seedlen);
    unsigned char cbuf[8];
    for (int i = 0; i < 8; i++) cbuf[i] = (unsigned char)((ctr >> (56 - 8*i)) & 0xFF);
    hasher.Write(cbuf, 8);
    unsigned char tmp[32];
    hasher.Finalize(tmp);
    memcpy(out32, tmp, 32);
}

static uint16_t u16_from_le(const unsigned char* p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

void DeriveInstance(const unsigned char* seed, size_t seedlen,
                    const SISParams& sp, SISInstance& out) {
    size_t total_values = (size_t)sp.n * sp.m + sp.n;
    out.A.resize((size_t)sp.n * sp.m);
    out.b.resize(sp.n);

    std::vector<unsigned char> buf;
    buf.reserve(total_values * 2 + 64);
    uint64_t ctr = 0;
    while (buf.size() < total_values * 2) {
        unsigned char block[32];
        sha256_ctr_xof(seed, seedlen, ctr++, block);
        buf.insert(buf.end(), block, block + 32);
    }

    size_t off = 0;
    for (uint32_t i = 0; i < sp.n; ++i) {
        for (uint32_t j = 0; j < sp.m; ++j) {
            uint16_t v = u16_from_le(&buf[off]); off += 2;
            out.A[(size_t)i * sp.m + j] = (uint16_t)(v % sp.q);
        }
    }
    for (uint32_t i = 0; i < sp.n; ++i) {
        uint16_t v = u16_from_le(&buf[off]); off += 2;
        out.b[i] = (uint16_t)(v % sp.q);
    }
}

bool DecodeTernary(const std::vector<unsigned char>& vch, uint32_t m, std::vector<int8_t>& x) {
    x.assign(m, 0);
    size_t need_bits = (size_t)m * 2;
    size_t need_bytes = (need_bits + 7) / 8;
    if (vch.size() < need_bytes) return false;

    size_t bitpos = 0;
    for (uint32_t i = 0; i < m; ++i) {
        size_t byte_idx = bitpos >> 3;
        int shift = bitpos & 7;
        uint8_t cur = vch[byte_idx];
        uint8_t next = (byte_idx + 1 < vch.size() ? vch[byte_idx + 1] : 0);
        uint8_t two = (uint8_t)(((cur >> shift) | (next << (8 - shift))) & 0x3);
        if (two == 0) x[i] = 0;
        else if (two == 1) x[i] = +1;
        else if (two == 3) x[i] = -1;
        else return false; // 10 invalid
        bitpos += 2;
    }
    return true;
}

bool VerifySIS(const SISInstance& I, const SISParams& sp, const std::vector<int8_t>& x) {
    if (x.size() != sp.m) return false;
    uint32_t w = 0;
    for (auto v : x) if (v != 0) ++w;
    if (w > sp.w) return false;

    const uint32_t q = sp.q;
    for (uint32_t i = 0; i < sp.n; ++i) {
        int64_t acc = 0;
        const uint16_t* Ai = &I.A[(size_t)i * sp.m];
        for (uint32_t j = 0; j < sp.m; ++j) {
            acc += (int64_t)Ai[j] * (int64_t)x[j];
        }
        int64_t mod = acc % (int64_t)q;
        if (mod < 0) mod += q;
        if ((uint16_t)mod != I.b[i]) return false;
    }
    return true;
}

} // namespace lattice

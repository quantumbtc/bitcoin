// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow.h>

#include <arith_uint256.h>
#include <chain.h>
#include <primitives/block.h>
#include <uint256.h>
#include <util/check.h>
#include <logging.h>
#include "chainparams.h"
#include "hash.h"
#include <cstring>
#include <consensus/params.h>
#include <crypto/sha256.h>
#include <util/strencodings.h>
#include <vector>
#include <cmath>
#include <limits>
#include "pow_quantum.h"

void PrintInt32Vector(const std::vector<unsigned char>& vch)
{
    if (vch.size() % 4 != 0) {
        std::cout << "Invalid vector size!" << std::endl;
        return;
    }
    std::cout << "Decoded vector = [";
    for (size_t i = 0; i < vch.size(); i += 4) {
        int32_t val;
        std::memcpy(&val, &vch[i], 4);
        std::cout << val;
        if (i + 4 != vch.size()) std::cout << ", ";
    }
    std::cout << "]" << std::endl;
}


unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader* pblock, const Consensus::Params& params)
{
    assert(pindexLast != nullptr);
    unsigned int nProofOfWorkLimit = UintToArith256(params.powLimit).GetCompact();

    // Only change once per difficulty adjustment interval
    if ((pindexLast->nHeight + 1) % params.DifficultyAdjustmentInterval() != 0) {
        if (params.fPowAllowMinDifficultyBlocks) {
            // Special difficulty rule for testnet:
            // If the new block's timestamp is more than 2* 10 minutes
            // then it MUST be a min-difficulty block.
            if (pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nPowTargetSpacing * 2)
                return nProofOfWorkLimit;
            else {
                // Return the last non-special-min-difficulty-rules-block
                const CBlockIndex* pindex = pindexLast;
                while (pindex->pprev && pindex->nHeight % params.DifficultyAdjustmentInterval() != 0 && pindex->nBits == nProofOfWorkLimit)
                    pindex = pindex->pprev;
                return pindex->nBits;
            }
        }
        return pindexLast->nBits;
    }

    // Go back by what we want to be 14 days worth of blocks
    int nHeightFirst = pindexLast->nHeight - (params.DifficultyAdjustmentInterval() - 1);
    assert(nHeightFirst >= 0);
    const CBlockIndex* pindexFirst = pindexLast->GetAncestor(nHeightFirst);
    assert(pindexFirst);

    return CalculateNextWorkRequired(pindexLast, pindexFirst->GetBlockTime(), params);
}

unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params& params)
{
    if (params.fPowNoRetargeting)
        return pindexLast->nBits;

    // Limit adjustment step
    int64_t nActualTimespan = pindexLast->GetBlockTime() - nFirstBlockTime;
    if (nActualTimespan < params.nPowTargetTimespan / 4)
        nActualTimespan = params.nPowTargetTimespan / 4;
    if (nActualTimespan > params.nPowTargetTimespan * 4)
        nActualTimespan = params.nPowTargetTimespan * 4;

    // Retarget
    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);
    arith_uint256 bnNew;

    // Special difficulty rule for Testnet4
    if (params.enforce_BIP94) {
        // Here we use the first block of the difficulty period. This way
        // the real difficulty is always preserved in the first block as
        // it is not allowed to use the min-difficulty exception.
        int nHeightFirst = pindexLast->nHeight - (params.DifficultyAdjustmentInterval() - 1);
        const CBlockIndex* pindexFirst = pindexLast->GetAncestor(nHeightFirst);
        bnNew.SetCompact(pindexFirst->nBits);
    } else {
        bnNew.SetCompact(pindexLast->nBits);
    }

    bnNew *= nActualTimespan;
    bnNew /= params.nPowTargetTimespan;

    if (bnNew > bnPowLimit)
        bnNew = bnPowLimit;

    return bnNew.GetCompact();
}

// Check that on difficulty adjustments, the new difficulty does not increase
// or decrease beyond the permitted limits.
bool PermittedDifficultyTransition(const Consensus::Params& params, int64_t height, uint32_t old_nbits, uint32_t new_nbits)
{
    if (params.fPowAllowMinDifficultyBlocks) return true;

    if (height % params.DifficultyAdjustmentInterval() == 0) {
        int64_t smallest_timespan = params.nPowTargetTimespan / 4;
        int64_t largest_timespan = params.nPowTargetTimespan * 4;

        const arith_uint256 pow_limit = UintToArith256(params.powLimit);
        arith_uint256 observed_new_target;
        observed_new_target.SetCompact(new_nbits);

        // Calculate the largest difficulty value possible:
        arith_uint256 largest_difficulty_target;
        largest_difficulty_target.SetCompact(old_nbits);
        largest_difficulty_target *= largest_timespan;
        largest_difficulty_target /= params.nPowTargetTimespan;

        if (largest_difficulty_target > pow_limit) {
            largest_difficulty_target = pow_limit;
        }

        // Round and then compare this new calculated value to what is
        // observed.
        arith_uint256 maximum_new_target;
        maximum_new_target.SetCompact(largest_difficulty_target.GetCompact());
        if (maximum_new_target < observed_new_target) return false;

        // Calculate the smallest difficulty value possible:
        arith_uint256 smallest_difficulty_target;
        smallest_difficulty_target.SetCompact(old_nbits);
        smallest_difficulty_target *= smallest_timespan;
        smallest_difficulty_target /= params.nPowTargetTimespan;

        if (smallest_difficulty_target > pow_limit) {
            smallest_difficulty_target = pow_limit;
        }

        // Round and then compare this new calculated value to what is
        // observed.
        arith_uint256 minimum_new_target;
        minimum_new_target.SetCompact(smallest_difficulty_target.GetCompact());
        if (minimum_new_target > observed_new_target) return false;
    } else if (old_nbits != new_nbits) {
        return false;
    }
    return true;
}

// Bypasses the actual proof of work check during fuzz testing with a simplified validation checking whether
// the most significant bit of the last byte of the hash is set.
bool CheckProofOfWork(const CBlockHeader& block, const Consensus::Params& params)
{
    if (EnableFuzzDeterminism()) return (block.GetHash().data()[31] & 0x80) == 0;
    
    // 根据POW类型选择验证方法
    switch (params.powType) {
        case Consensus::Params::PowType::SHA256D: {
            auto bnTarget{DeriveTarget(block.nBits, params.powLimit)};
            if (!bnTarget) return false;
            return CheckProofOfWorkImpl(block.GetHash(), block.nBits, params);
        }
        case Consensus::Params::PowType::LATTICE_SIS: {
            auto bnTarget{DeriveTarget(block.nBits, params.powLimit)};
            if (!bnTarget) return false;
            if (!CheckProofOfWorkSIS(block, params)) return false;
            return CheckProofOfWorkImpl(block.GetHash(), block.nBits, params);
        }
        case Consensus::Params::PowType::QUANTUM_NTRU: {
            if (!CheckQuantumProofOfWork(block, params)) return false;
            return true; // 抗量子POW不需要额外的哈希验证
        }
        default:
            return false;
    }
}

std::optional<arith_uint256> DeriveTarget(unsigned int nBits, const uint256 pow_limit)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(pow_limit))
        return {};

    return bnTarget;
}

bool CheckProofOfWorkImpl(uint256 hash, unsigned int nBits, const Consensus::Params& params)
{
    auto bnTarget{DeriveTarget(nBits, params.powLimit)};
    if (!bnTarget) return false;
    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget)
        return false;

    return true;
}


// -----------------------------
// 工具：把 uint32_t 追加到字节向量 (LE)
// -----------------------------
static inline void AppendLE32(std::vector<unsigned char>& out, uint32_t v)
{
    out.push_back((unsigned char)(v & 0xff));
    out.push_back((unsigned char)((v >> 8) & 0xff));
    out.push_back((unsigned char)((v >> 16) & 0xff));
    out.push_back((unsigned char)((v >> 24) & 0xff));
}

// -----------------------------
// 从区块头构造 "header seed"
// 建议：使用 header 中除 vchPowSolution 之外的字段
// -----------------------------
static void HeaderSeed(const CBlockHeader& header, std::vector<unsigned char>& seed32)
{
    // 用简洁稳定的方式：直接取 header 哈希（如果你的 GetHash() 包含 vchPowSolution，
    // 可改为 GetHashWithoutSolution()；这里假设影响可忽略或你已调整）
    uint256 h = header.GetHash();
    seed32.assign(h.begin(), h.end()); // 32 bytes
}

// -----------------------------
// 由 header_seed 展开 A[i,j] ∈ [0,q)
// A 按行存储：A[i*m + j]
// 使用 SHA256(seed || i || j) 取前2字节 mod q
// -----------------------------
static void DeriveMatrixA(const std::vector<unsigned char>& seed32,
                          int n, int m, int q,
                          std::vector<uint16_t>& A)
{
    A.assign((size_t)n * m, 0);
    std::vector<unsigned char> buf;
    buf.reserve(seed32.size() + 8);
    for (int i = 0; i < n; ++i) {
        for (int j = 0; j < m; ++j) {
            buf.clear();
            buf.insert(buf.end(), seed32.begin(), seed32.end());
            AppendLE32(buf, (uint32_t)i);
            AppendLE32(buf, (uint32_t)j);

            // SHA256
            CSHA256 hasher;
            unsigned char out[32];
            hasher.Write(buf.data(), buf.size()).Finalize(out);

            // 取前 16 bits，映射到 [0,q)
            uint16_t v = (uint16_t(out[0]) | (uint16_t(out[1]) << 8));
            if (q < 65536)
                v = (uint16_t)(v % q);
            else
                v = (uint16_t)v; // q>65535 不会发生（我们的 q=12289）
            A[(size_t)i * m + j] = v;
        }
    }
}

// -----------------------------
// 解包 2bit 编码的 {-1,0,+1}^m 向量：00=0, 01=+1, 11=-1
// -----------------------------
static bool UnpackTernary2b(const std::vector<unsigned char>& vch, int m, std::vector<int8_t>& x_out)
{
    const size_t need_bits = (size_t)m * 2;
    const size_t need_bytes = (need_bits + 7) / 8;
    if (vch.size() < need_bytes) return false;
    x_out.assign(m, 0);

    size_t bitpos = 0;
    for (int i = 0; i < m; ++i) {
        const size_t byte_idx = bitpos >> 3;
        const int shift = bitpos & 7;
        const uint8_t cur = vch[byte_idx];
        const uint8_t next = (byte_idx + 1 < vch.size()) ? vch[byte_idx + 1] : 0;
        // 取2位
        uint8_t two = (uint8_t)(((cur >> shift) | (uint16_t(next) << (8 - shift))) & 0x03);
        if (two == 0)
            x_out[i] = 0; // 00
        else if (two == 1)
            x_out[i] = +1; // 01
        else if (two == 3)
            x_out[i] = -1; // 11
        else
            return false; // 10 为非法
        bitpos += 2;
    }
    return true;
}

// -----------------------------
// 计算 y = A x mod q（A按行存储）
// -----------------------------
static void MatVecMod(const std::vector<uint16_t>& A,
                      const std::vector<int8_t>& x,
                      int n, int m, int q,
                      std::vector<int>& y)
{
    y.assign(n, 0);
    for (int i = 0; i < n; ++i) {
        int32_t acc = 0;
        const uint16_t* row = &A[(size_t)i * m];
        for (int j = 0; j < m; ++j) {
            const int8_t v = x[j];
            if (!v) continue;
            // -a == q-a (mod q)
            acc += (v == 1 ? row[j] : (q - row[j]));
            if (acc >= q) acc -= q; // 轻微避免溢出
        }
        y[i] = acc % q;
    }
}

// -----------------------------
// 把 y 映射到中心代表区间 [-q/2, q/2] ，并测量 ||y||_∞
// -----------------------------
static int LinfCentered(const std::vector<int>& y, int q)
{
    const int half = q / 2;
    int mx = 0;
    for (int v : y) {
        int c = v;
        if (c > half) c -= q;
        if (c < -half) c += q;
        int a = std::abs(c);
        if (a > mx) mx = a;
    }
    return mx;
}

// -----------------------------
// 计算 ||x||_0（对三元向量等于 L2^2）
// -----------------------------
static uint32_t L0(const std::vector<int8_t>& x)
{
    uint32_t s = 0;
    for (int8_t v : x)
        if (v) ++s;
    return s;
}

// -----------------------------
// 可选：按 nBits 映射到残差阈值 r（示例映射，可自行调整/离散表）
// 思路：难度越高（target 越小），要求 r 越小
// -----------------------------
static int MapNBitsToR(uint32_t nBits, int q)
{
    // 例：把 compact target 的高字节当作粗糙难度指标
    // （你可以替换为精确 target→期望残差 的函数或查表）
    unsigned int exponent = (nBits >> 24) & 0xff;
    // 让 r 在 [1, q/8] 之间变化
    int r = std::max(1, (q >> 3) - (int)exponent);
    // 也可直接返回固定值（如 8/16/32），或者从 chainparams 读取
    return r;
}

// -----------------------------
// 主验证：CheckProofOfWorkSIS
// - 从 header 派生 A
// - 解包 vchPowSolution → x
// - 检查 ||x||_0 == w
// - 计算 y = A x mod q，测 ||y||_∞ ≤ r
// -----------------------------
bool CheckProofOfWorkSIS(const CBlockHeader& header, const Consensus::Params& params)
{
    const int n = params.sis_n;
    const int m = params.sis_m;
    const int q = params.sis_q;
    const int w = params.sis_w;

    // 1) 解包解向量
    std::vector<int8_t> x;
    if (header.vchPowSolution.empty()) {
        // 创世或过渡阶段：如果你想允许空解，放开此判断
        // return false; // 正式主网请启用强校验
        return true; // 建议默认不接受空解
    }
    if (!UnpackTernary2b(header.vchPowSolution, m, x)) {
        return false; // "Failed to decode solution vector"
    }
    if ((int)L0(x) != w) {
        // 你也可以改为 L0(x) <= w
        return false;
    }

    // 2) 从 header 构造种子并派生矩阵 A
    std::vector<unsigned char> seed32;
    HeaderSeed(header, seed32);

    std::vector<uint16_t> A;
    DeriveMatrixA(seed32, n, m, q, A);

    // 3) 计算 y = A x mod q → 测 ||·||_∞
    std::vector<int> y;
    MatVecMod(A, x, n, m, q, y);

    int r = params.sis_dynamic_r ? MapNBitsToR(header.nBits, q) : params.sis_r_fixed;

    // 严格 SIS：把 r 设为 0 即可
    int linf = LinfCentered(y, q);
    if (linf > r) {
        return false;
    }

    return true;
}

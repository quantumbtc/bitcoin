// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow_quantum.h>

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
#include <random>
#include <algorithm>

// 抗量子POW算法：简化NTRU格密码学
// 基于多项式环 R = Z[x]/(x^N + 1) 的格问题

namespace QuantumPOW {

// 多项式环参数
constexpr uint32_t N = 256;  // 多项式次数
constexpr uint32_t Q = 12289; // 模数
constexpr uint32_t P = 3;     // 小模数
constexpr uint32_t D = 64;    // 稀疏度参数

// 多项式结构
struct Polynomial {
    std::vector<int32_t> coeffs;
    
    Polynomial() : coeffs(N, 0) {}
    
    // 多项式加法
    Polynomial operator+(const Polynomial& other) const {
        Polynomial result;
        for (size_t i = 0; i < N; ++i) {
            result.coeffs[i] = (coeffs[i] + other.coeffs[i]) % Q;
            if (result.coeffs[i] < 0) result.coeffs[i] += Q;
        }
        return result;
    }
    
    // 多项式乘法（循环卷积）
    Polynomial operator*(const Polynomial& other) const {
        Polynomial result;
        for (size_t i = 0; i < N; ++i) {
            for (size_t j = 0; j < N; ++j) {
                size_t k = (i + j) % N;
                int64_t prod = static_cast<int64_t>(coeffs[i]) * other.coeffs[j];
                if (k < N/2) {
                    result.coeffs[k] = (result.coeffs[k] + prod) % Q;
                } else {
                    result.coeffs[k] = (result.coeffs[k] - prod) % Q;
                }
                if (result.coeffs[k] < 0) result.coeffs[k] += Q;
            }
        }
        return result;
    }
    
    // 模P运算
    Polynomial modP() const {
        Polynomial result;
        for (size_t i = 0; i < N; ++i) {
            result.coeffs[i] = coeffs[i] % P;
            if (result.coeffs[i] < 0) result.coeffs[i] += P;
        }
        return result;
    }
    
    // 计算L2范数
    double L2Norm() const {
        double sum = 0.0;
        for (int32_t coeff : coeffs) {
            sum += static_cast<double>(coeff) * coeff;
        }
        return std::sqrt(sum);
    }
    
    // 计算L∞范数
    int32_t LInfNorm() const {
        int32_t max_val = 0;
        for (int32_t coeff : coeffs) {
            int32_t abs_coeff = std::abs(coeff);
            if (abs_coeff > max_val) max_val = abs_coeff;
        }
        return max_val;
    }
};

// 生成随机稀疏多项式
Polynomial GenerateSparsePolynomial(uint32_t seed, uint32_t density) {
    Polynomial poly;
    std::mt19937 gen(seed);
    std::uniform_int_distribution<> dist(0, N-1);
    std::uniform_int_distribution<> sign_dist(0, 1);
    
    for (uint32_t i = 0; i < density; ++i) {
        uint32_t pos = dist(gen);
        int32_t sign = sign_dist(gen) ? 1 : -1;
        poly.coeffs[pos] = sign;
    }
    
    return poly;
}

// 从区块头生成种子
std::vector<uint8_t> GenerateSeed(const CBlockHeader& header) {
    // 使用除vchPowSolution外的所有字段
    std::vector<uint8_t> data;
    data.reserve(80); // 标准区块头大小
    
    // 序列化区块头（不包含vchPowSolution）
    for (int i = 0; i < 4; ++i) {
        data.push_back((header.nVersion >> (i * 8)) & 0xFF);
    }
    
    for (int i = 0; i < 32; ++i) {
        data.push_back(header.hashPrevBlock.begin()[i]);
    }
    
    for (int i = 0; i < 32; ++i) {
        data.push_back(header.hashMerkleRoot.begin()[i]);
    }
    
    for (int i = 0; i < 4; ++i) {
        data.push_back((header.nTime >> (i * 8)) & 0xFF);
    }
    
    for (int i = 0; i < 4; ++i) {
        data.push_back((header.nBits >> (i * 8)) & 0xFF);
    }
    
    for (int i = 0; i < 4; ++i) {
        data.push_back((header.nNonce >> (i * 8)) & 0xFF);
    }
    
    return data;
}

// 从种子生成公钥多项式
Polynomial GeneratePublicKey(const std::vector<uint8_t>& seed) {
    Polynomial f, g;
    
    // 使用种子生成确定性随机数
    uint32_t seed_value = 0;
    for (size_t i = 0; i < seed.size(); ++i) {
        seed_value = seed_value * 31 + seed[i];
    }
    
    // 生成稀疏多项式f和g
    f = GenerateSparsePolynomial(seed_value, D);
    g = GenerateSparsePolynomial(seed_value + 1, D);
    
    // 计算公钥 h = g * f^(-1) mod q
    // 简化：直接返回f*g作为公钥
    return f * g;
}

// 验证POW解
bool VerifyQuantumPOW(const CBlockHeader& header, const Consensus::Params& params) {
    if (header.vchPowSolution.empty()) {
        return false; // 必须提供解
    }
    
    // 解包解向量（假设存储为多项式系数）
    if (header.vchPowSolution.size() != N * 4) { // 每个系数4字节
        return false;
    }
    
    // 重建多项式
    Polynomial solution;
    for (size_t i = 0; i < N; ++i) {
        int32_t coeff = 0;
        for (int j = 0; j < 4; ++j) {
            coeff |= static_cast<int32_t>(header.vchPowSolution[i * 4 + j]) << (j * 8);
        }
        solution.coeffs[i] = coeff;
    }
    
    // 生成种子和公钥
    auto seed = GenerateSeed(header);
    auto public_key = GeneratePublicKey(seed);
    
    // 计算挑战：h * solution mod q
    auto challenge = public_key * solution;
    
    // 验证约束条件
    double l2_norm = challenge.L2Norm();
    int32_t linf_norm = challenge.LInfNorm();
    
    // 根据难度调整阈值
    uint32_t target = header.nBits;
    double l2_threshold = params.quantum_l2_threshold * (1.0 + (target >> 24) * 0.1);
    int32_t linf_threshold = params.quantum_linf_threshold + (target >> 24) * 2;
    
    // 检查L2范数
    if (l2_norm > l2_threshold) {
        return false;
    }
    
    // 检查L∞范数
    if (linf_norm > linf_threshold) {
        return false;
    }
    
    // 检查解的稀疏性
    uint32_t non_zero_count = 0;
    for (int32_t coeff : solution.coeffs) {
        if (coeff != 0) non_zero_count++;
    }
    
    if (non_zero_count > params.quantum_max_density) {
        return false;
    }
    
    return true;
}

// 计算目标难度对应的阈值
std::pair<double, int32_t> CalculateThresholds(uint32_t nBits, const Consensus::Params& params) {
    double l2_threshold = params.quantum_l2_threshold;
    int32_t linf_threshold = params.quantum_linf_threshold;
    
    // 根据难度调整阈值
    uint32_t exponent = (nBits >> 24) & 0xFF;
    double difficulty_factor = 1.0 + (exponent * 0.05);
    
    l2_threshold *= difficulty_factor;
    linf_threshold += static_cast<int32_t>(exponent * 2);
    
    return {l2_threshold, linf_threshold};
}

// 生成POW解（挖矿）
bool GenerateQuantumPOW(const CBlockHeader& header, const Consensus::Params& params, 
                        std::vector<uint8_t>& solution) {
    auto seed = GenerateSeed(header);
    auto public_key = GeneratePublicKey(seed);
    
    auto [l2_threshold, linf_threshold] = CalculateThresholds(header.nBits, params);
    
    // 尝试不同的随机种子
    uint32_t attempt = 0;
    const uint32_t max_attempts = 1000000;
    
    while (attempt < max_attempts) {
        // 生成候选解
        Polynomial candidate = GenerateSparsePolynomial(attempt, params.quantum_max_density);
        
        // 计算挑战
        auto challenge = public_key * candidate;
        
        // 检查是否满足条件
        if (challenge.L2Norm() <= l2_threshold && 
            challenge.LInfNorm() <= linf_threshold) {
            
            // 序列化解
            solution.clear();
            solution.reserve(N * 4);
            
            for (int32_t coeff : candidate.coeffs) {
                for (int j = 0; j < 4; ++j) {
                    solution.push_back((coeff >> (j * 8)) & 0xFF);
                }
            }
            
            return true;
        }
        
        attempt++;
    }
    
    return false;
}

} // namespace QuantumPOW

// 导出函数
bool CheckQuantumProofOfWork(const CBlockHeader& header, const Consensus::Params& params) {
    return QuantumPOW::VerifyQuantumPOW(header, params);
}

bool GenerateQuantumProofOfWork(const CBlockHeader& header, const Consensus::Params& params,
                               std::vector<uint8_t>& solution) {
    return QuantumPOW::GenerateQuantumPOW(header, params, solution);
}

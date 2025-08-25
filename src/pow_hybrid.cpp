// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "pow_hybrid.h"
#include <consensus/params.h>
#include <primitives/block.h>
#include <crypto/sha256.h>
#include <vector>
#include <cmath>
#include <random>

// 多项式结构（用于抗量子POW）
struct Polynomial {
    std::vector<int32_t> coeffs;
    
    Polynomial(size_t size = 256) : coeffs(size, 0) {}
    
    // 生成随机稀疏多项式
    void GenerateRandom(uint32_t seed, uint32_t density) {
        std::mt19937 gen(seed);
        std::uniform_int_distribution<> dist(0, coeffs.size() - 1);
        std::uniform_int_distribution<> sign_dist(0, 1);
        
        // 清零
        std::fill(coeffs.begin(), coeffs.end(), 0);
        
        // 随机设置非零系数
        for (uint32_t i = 0; i < density; ++i) {
            uint32_t pos = dist(gen);
            int32_t sign = sign_dist(gen) ? 1 : -1;
            coeffs[pos] = sign;
        }
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
    
    // 计算非零系数数量
    uint32_t NonZeroCount() const {
        uint32_t count = 0;
        for (int32_t coeff : coeffs) {
            if (coeff != 0) count++;
        }
        return count;
    }
};

// 从区块头生成种子（排除vchPowSolution字段）
static uint32_t GenerateHeaderSeed(const CBlockHeader& header) {
    // 使用除vchPowSolution外的所有字段生成种子
    uint32_t seed = header.nVersion + header.nTime + header.nBits + header.nNonce;
    
    // 添加Merkle根的影响
    for (int i = 0; i < 8; ++i) {
        seed += (header.hashMerkleRoot.GetUint64(i/8) >> ((i%8) * 8)) & 0xFF;
    }
    
    return seed;
}

// 检查混合POW：传统哈希 + 抗量子验证
bool CheckHybridProofOfWork(const CBlockHeader& header, const Consensus::Params& params) {
    // 检查是否提供抗量子POW解
    if (header.vchPowSolution.empty()) {
        return false;
    }
    
    // 从解重建多项式
    Polynomial solution;
    if (header.vchPowSolution.size() >= solution.coeffs.size() * 4) {
        for (size_t i = 0; i < solution.coeffs.size(); ++i) {
            int32_t coeff = 0;
            for (int j = 0; j < 4; ++j) {
                if (i * 4 + j < header.vchPowSolution.size()) {
                    coeff |= static_cast<int32_t>(header.vchPowSolution[i * 4 + j]) << (j * 8);
                }
            }
            solution.coeffs[i] = coeff;
        }
    }
    
    // 验证抗量子约束条件
    double l2_norm = solution.L2Norm();
    int32_t linf_norm = solution.LInfNorm();
    uint32_t density = solution.NonZeroCount();
    
    // 使用共识参数中的阈值
    double l2_threshold = params.quantum_l2_threshold;
    int32_t linf_threshold = params.quantum_linf_threshold;
    uint32_t max_density = params.quantum_max_density;
    
    // 根据难度调整阈值（可选）
    uint32_t difficulty_shift = (header.nBits >> 24) & 0xFF;
    if (difficulty_shift > 0) {
        double difficulty_factor = 1.0 / (1.0 + difficulty_shift * 0.05);
        l2_threshold *= difficulty_factor;
        linf_threshold = std::max(1, static_cast<int32_t>(linf_threshold * difficulty_factor));
        if (difficulty_shift > 5) {
            max_density = std::max(16u, max_density - (difficulty_shift - 5) * 4);
        }
    }
    
    // 检查所有约束条件
    if (l2_norm > l2_threshold) {
        return false;
    }
    
    if (linf_norm > linf_threshold) {
        return false;
    }
    
    if (density > max_density) {
        return false;
    }
    
    return true;
}

// 生成混合POW解
bool GenerateHybridProofOfWork(const CBlockHeader& header, const Consensus::Params& params,
                              std::vector<uint8_t>& solution) {
    // 设置参数
    double l2_threshold = params.quantum_l2_threshold;
    int32_t linf_threshold = params.quantum_linf_threshold;
    uint32_t max_density = params.quantum_max_density;
    
    // 根据难度调整阈值
    uint32_t difficulty_shift = (header.nBits >> 24) & 0xFF;
    if (difficulty_shift > 0) {
        double difficulty_factor = 1.0 / (1.0 + difficulty_shift * 0.05);
        l2_threshold *= difficulty_factor;
        linf_threshold = std::max(1, static_cast<int32_t>(linf_threshold * difficulty_factor));
        if (difficulty_shift > 5) {
            max_density = std::max(16u, max_density - (difficulty_shift - 5) * 4);
        }
    }
    
    // 尝试生成满足条件的解
    const uint32_t max_attempts = 100000;
    
    for (uint32_t attempt = 0; attempt < max_attempts; ++attempt) {
        // 生成候选解
        Polynomial candidate;
        candidate.GenerateRandom(GenerateHeaderSeed(header) + attempt, max_density / 2);
        
        // 检查是否满足条件
        if (candidate.L2Norm() <= l2_threshold && 
            candidate.LInfNorm() <= linf_threshold &&
            candidate.NonZeroCount() <= max_density) {
            
            // 序列化解
            solution.clear();
            solution.reserve(candidate.coeffs.size() * 4);
            
            for (int32_t coeff : candidate.coeffs) {
                for (int j = 0; j < 4; ++j) {
                    solution.push_back((coeff >> (j * 8)) & 0xFF);
                }
            }
            
            return true;
        }
    }
    
    return false;
}

// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "pow_hybrid.h"
#include <consensus/params.h>
#include <primitives/block.h>
#include <crypto/sha256.h>
#include <hash.h>
#include <arith_uint256.h>

#include <vector>
#include <cmath>
#include <random>
#include <iostream>

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
        std::cout << "检查是否提供抗量子POW解为空 header.vchPowSolution.empty()..." << std::endl;
        return false;
    }
    
    // 从解重建多项式
    Polynomial solution;
    if (header.vchPowSolution.size() < solution.coeffs.size() * 4) {
        // 解太小，无法重建完整的256个系数
        std::cout << "解太小，无法重建完整的256个系数 vchPowSolution<coeffs [" << header.vchPowSolution.size() << "<" << solution.coeffs.size() * 4
                  << "]..." << std::endl;
        return false;
    }
    
    for (size_t i = 0; i < solution.coeffs.size(); ++i) {
        int32_t coeff = 0;
        for (int j = 0; j < 4; ++j) {
            coeff |= static_cast<int32_t>(header.vchPowSolution[i * 4 + j]) << (j * 8);
        }
        solution.coeffs[i] = coeff;
    }
    
    // 验证抗量子约束条件（基础验证）
    double l2_norm = solution.L2Norm();
    int32_t linf_norm = solution.LInfNorm();
    uint32_t density = solution.NonZeroCount();
    
    // 使用共识参数中的阈值
    double l2_threshold = params.quantum_l2_threshold;
    int32_t linf_threshold = params.quantum_linf_threshold;
    uint32_t max_density = params.quantum_max_density;
    
    // 基础约束检查
    if (l2_norm > l2_threshold || linf_norm > linf_threshold || density > max_density) {
        std::cout << "基础约束检查 (不符合) l2_norm>l2_threshold:[" << l2_norm << ">" << l2_threshold << "],linf_norm>linf_threshold:["
                  << linf_norm << ">" << linf_threshold << "density>max_density:[" << density << ">" << max_density
                  << "]..." << std::endl;
        return false;
    }
    
    // 将区块头信息与抗量子解组合，计算SHA256哈希
    HashWriter hasher;
    
    // 添加区块头字段（排除vchPowSolution）
    hasher << header.nVersion;
    hasher << header.hashPrevBlock;
    hasher << header.hashMerkleRoot;
    hasher << header.nTime;
    hasher << header.nBits;
    hasher << header.nNonce;
    
    // 添加抗量子解
    hasher << header.vchPowSolution;
    
    uint256 hash = hasher.GetHash();
    
    // 将哈希转换为arith_uint256以便与难度比较
    arith_uint256 target = arith_uint256().SetCompact(header.nBits);
    arith_uint256 hash_arith = UintToArith256(hash);
    
    std::cout << "哈希转换为arith_uint256以便与难度比较: " << hash_arith.ToString() << "<" << target.ToString() << std::endl;
    
    // 检查哈希是否小于目标难度
    return hash_arith < target;
}

// 生成混合POW解
bool GenerateHybridProofOfWork(const CBlockHeader& header, const Consensus::Params& params) {
    // 设置参数
    uint32_t max_density = params.quantum_max_density;

     // 生成候选解
    Polynomial candidate;
    candidate.GenerateRandom(GenerateHeaderSeed(header), max_density / 2);
    // 序列化候选解
    std::vector<uint8_t> solution;
    solution.reserve(candidate.coeffs.size() * 4);
    for (int32_t coeff : candidate.coeffs) {
        for (int j = 0; j < 4; ++j) {
            solution.push_back((coeff >> (j * 8)) & 0xFF);
        }
    }
    header.vchPowSolution = PackTernary2b(solution);
    return true;
}

std::vector<unsigned char> PackTernary2b(const std::vector<int8_t>& x)
{
    size_t bits = x.size() * 2;
    size_t nbytes = (bits + 7) / 8;
    std::vector<unsigned char> out(nbytes, 0);
    size_t bitpos = 0;
    for (int8_t v : x) {
        uint8_t code = (v == 0) ? 0 : (v == 1) ? 1 :
                                                 3; // 00,01,11
        size_t byte_idx = bitpos >> 3;
        int shift = bitpos & 7;
        out[byte_idx] |= (code << shift);
        if (shift > 6) out[byte_idx + 1] |= (code >> (8 - shift));
        bitpos += 2;
    }
    return out;
}

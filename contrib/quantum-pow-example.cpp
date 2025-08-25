// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * 抗量子POW算法示例程序
 * 
 * 该程序演示了如何使用新实现的抗量子POW算法
 * 进行区块挖矿和验证。
 */

#include <iostream>
#include <chrono>
#include <thread>
#include <vector>
#include <random>
#include <iomanip>

// 简化的多项式结构（用于演示）
struct SimplePolynomial {
    std::vector<int32_t> coeffs;
    
    SimplePolynomial(size_t size = 256) : coeffs(size, 0) {}
    
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

// 模拟的区块头结构
struct MockBlockHeader {
    uint32_t nVersion = 1;
    uint32_t nTime = 1234567890;
    uint32_t nBits = 0x1e0ffff0;
    uint32_t nNonce = 0;
    std::vector<uint8_t> vchPowSolution;
    
    // 模拟种子生成
    uint32_t GenerateSeed() const {
        return nVersion + nTime + nBits + nNonce;
    }
};

// 模拟的抗量子POW验证
bool MockVerifyQuantumPOW(const MockBlockHeader& header, 
                          double l2_threshold, 
                          int32_t linf_threshold, 
                          uint32_t max_density) {
    if (header.vchPowSolution.empty()) {
        return false;
    }
    
    // 从解重建多项式
    SimplePolynomial solution;
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
    
    // 验证约束条件
    double l2_norm = solution.L2Norm();
    int32_t linf_norm = solution.LInfNorm();
    uint32_t density = solution.NonZeroCount();
    
    std::cout << "  L2范数: " << std::fixed << std::setprecision(2) << l2_norm 
              << " (阈值: " << l2_threshold << ")" << std::endl;
    std::cout << "  L∞范数: " << linf_norm 
              << " (阈值: " << linf_threshold << ")" << std::endl;
    std::cout << "  稀疏度: " << density 
              << " (最大: " << max_density << ")" << std::endl;
    
    return l2_norm <= l2_threshold && 
           linf_norm <= linf_threshold && 
           density <= max_density;
}

// 模拟的抗量子POW生成
bool MockGenerateQuantumPOW(MockBlockHeader& header, 
                           double l2_threshold, 
                           int32_t linf_threshold, 
                           uint32_t max_density,
                           uint32_t max_attempts = 100000) {
    
    std::cout << "开始挖矿，最大尝试次数: " << max_attempts << std::endl;
    std::cout << "目标阈值 - L2: " << l2_threshold << ", L∞: " << linf_threshold << std::endl;
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    for (uint32_t attempt = 0; attempt < max_attempts; ++attempt) {
        // 更新nonce
        header.nNonce = attempt;
        
        // 生成候选解
        SimplePolynomial candidate;
        candidate.GenerateRandom(header.GenerateSeed(), max_density / 2);
        
        // 检查是否满足条件
        if (candidate.L2Norm() <= l2_threshold && 
            candidate.LInfNorm() <= linf_threshold &&
            candidate.NonZeroCount() <= max_density) {
            
            // 序列化解
            header.vchPowSolution.clear();
            header.vchPowSolution.reserve(candidate.coeffs.size() * 4);
            
            for (int32_t coeff : candidate.coeffs) {
                for (int j = 0; j < 4; ++j) {
                    header.vchPowSolution.push_back((coeff >> (j * 8)) & 0xFF);
                }
            }
            
            auto end_time = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
            
            std::cout << "找到解！尝试次数: " << attempt << std::endl;
            std::cout << "耗时: " << duration.count() << " ms" << std::endl;
            std::cout << "哈希率: " << (attempt / (duration.count() / 1000.0)) << " H/s" << std::endl;
            
            return true;
        }
        
        // 显示进度
        if (attempt % 10000 == 0 && attempt > 0) {
            auto now = std::chrono::high_resolution_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - start_time);
            double rate = attempt / (elapsed.count() / 1000.0);
            std::cout << "进度: " << attempt << "/" << max_attempts 
                      << " (" << (attempt * 100.0 / max_attempts) << "%) "
                      << "速率: " << std::fixed << std::setprecision(2) << rate << " H/s" << std::endl;
        }
    }
    
    std::cout << "未找到解，达到最大尝试次数" << std::endl;
    return false;
}

int main() {
    std::cout << "=== 抗量子POW算法演示程序 ===" << std::endl;
    std::cout << std::endl;
    
    // 创建模拟区块头
    MockBlockHeader header;
    
    // 设置POW参数
    double l2_threshold = 100.0;
    int32_t linf_threshold = 50;
    uint32_t max_density = 128;
    
    std::cout << "区块头信息:" << std::endl;
    std::cout << "  版本: " << header.nVersion << std::endl;
    std::cout << "  时间: " << header.nTime << std::endl;
    std::cout << "  难度: 0x" << std::hex << header.nBits << std::dec << std::endl;
    std::cout << "  种子: " << header.GenerateSeed() << std::endl;
    std::cout << std::endl;
    
    // 尝试生成POW解
    std::cout << "开始生成抗量子POW解..." << std::endl;
    bool success = MockGenerateQuantumPOW(header, l2_threshold, linf_threshold, max_density, 50000);
    
    if (success) {
        std::cout << std::endl;
        std::cout << "POW解生成成功！" << std::endl;
        std::cout << "解大小: " << header.vchPowSolution.size() << " 字节" << std::endl;
        std::cout << "最终nonce: " << header.nNonce << std::endl;
        
        // 验证解
        std::cout << std::endl;
        std::cout << "验证POW解..." << std::endl;
        bool valid = MockVerifyQuantumPOW(header, l2_threshold, linf_threshold, max_density);
        
        if (valid) {
            std::cout << "✓ POW验证通过！" << std::endl;
        } else {
            std::cout << "✗ POW验证失败！" << std::endl;
        }
    } else {
        std::cout << "POW解生成失败" << std::endl;
    }
    
    std::cout << std::endl;
    std::cout << "=== 演示结束 ===" << std::endl;
    
    return 0;
}

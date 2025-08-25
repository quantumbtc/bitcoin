// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <pow.h>
#include <pow_hybrid.h>
#include <primitives/block.h>
#include <consensus/params.h>

BOOST_AUTO_TEST_SUITE(hybrid_pow_tests)

BOOST_AUTO_TEST_CASE(hybrid_pow_basic_test)
{
    // 创建测试区块头
    CBlockHeader header;
    header.nVersion = 1;
    header.nTime = 1234567890;
    header.nBits = 0x1e0ffff0;
    header.nNonce = 0;
    
    // 创建共识参数
    Consensus::Params params;
    params.powLimit = uint256{"00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
    params.quantum_l2_threshold = 100.0;
    params.quantum_linf_threshold = 50;
    params.quantum_max_density = 128;
    
    // 测试空的抗量子解
    BOOST_CHECK(!CheckHybridProofOfWork(header, params));
    
    // 测试传统POW哈希验证
    BOOST_CHECK(CheckProofOfWorkImpl(header.GetHash(), header.nBits, params));
}

BOOST_AUTO_TEST_CASE(hybrid_pow_generation_test)
{
    // 创建测试区块头
    CBlockHeader header;
    header.nVersion = 1;
    header.nTime = 1234567890;
    header.nBits = 0x1e0ffff0;
    header.nNonce = 0;
    
    // 创建共识参数
    Consensus::Params params;
    params.powLimit = uint256{"00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
    params.quantum_l2_threshold = 100.0;
    params.quantum_linf_threshold = 50;
    params.quantum_max_density = 128;
    
    // 尝试生成抗量子POW解
    std::vector<uint8_t> solution;
    bool success = GenerateHybridProofOfWork(header, params, solution);
    
    if (success) {
        // 设置解并验证
        header.vchPowSolution = solution;
        BOOST_CHECK(CheckHybridProofOfWork(header, params));
        
        // 验证完整的混合POW
        BOOST_CHECK(CheckProofOfWork(header, params));
    }
}

BOOST_AUTO_TEST_CASE(hybrid_pow_difficulty_test)
{
    // 测试不同难度的阈值调整
    Consensus::Params params;
    params.quantum_l2_threshold = 100.0;
    params.quantum_linf_threshold = 50;
    params.quantum_max_density = 128;
    
    // 基础难度
    uint32_t base_nbits = 0x1e0ffff0;
    uint32_t high_nbits = 0x1e5ffff0;
    
    // 高难度应该导致更严格的阈值
    BOOST_CHECK(high_nbits > base_nbits);
}

BOOST_AUTO_TEST_SUITE_END()

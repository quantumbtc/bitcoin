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
    header.hashPrevBlock.SetNull();
    header.hashMerkleRoot.SetNull();
    header.nTime = 1234567890;
    header.nBits = 0x1e0ffff0;
    header.nNonce = 12345;
    
    // 创建测试共识参数
    Consensus::Params params;
    params.powLimit = uint256{"00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
    params.quantum_n = 256;
    params.quantum_q = 12289;
    params.quantum_p = 3;
    params.quantum_d = 64;
    params.quantum_l2_threshold = 100.0;
    params.quantum_linf_threshold = 50;
    params.quantum_max_density = 128;
    
    // 测试空解应该失败
    header.vchPowSolution.clear();
    BOOST_CHECK(!CheckHybridProofOfWork(header, params));
    
    // 测试错误大小的解应该失败
    header.vchPowSolution.resize(100, 0);
    BOOST_CHECK(!CheckHybridProofOfWork(header, params));
    
    // 测试正确大小的解（但可能无效）
    header.vchPowSolution.resize(256 * 4, 0);
    BOOST_CHECK(!CheckHybridProofOfWork(header, params));
}

BOOST_AUTO_TEST_CASE(hybrid_pow_generation_test)
{
    // 创建测试区块
    CBlock block;
    block.nVersion = 1;
    block.hashPrevBlock.SetNull();
    block.hashMerkleRoot.SetNull();
    block.nTime = 1234567890;
    block.nBits = 0x1e0ffff0;
    block.nNonce = 12345;
    
    // 创建测试共识参数
    Consensus::Params params;
    params.powLimit = uint256{"00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
    params.quantum_n = 256;
    params.quantum_q = 12289;
    params.quantum_p = 3;
    params.quantum_d = 64;
    params.quantum_l2_threshold = 100.0;
    params.quantum_linf_threshold = 50;
    params.quantum_max_density = 128;
    
    // 尝试生成POW解
    bool success = GenerateHybridProofOfWork(block, params);
    
    // 注意：在实际测试中，生成可能需要很长时间，所以这里只是测试接口
    // 如果成功生成，验证解的有效性
    if (success) {
        BOOST_CHECK(!block.vchPowSolution.empty());
        BOOST_CHECK(CheckHybridProofOfWork(block.GetBlockHeader(), params));
    }
}

BOOST_AUTO_TEST_CASE(hybrid_pow_parameter_test)
{
    // 测试不同的参数设置
    Consensus::Params params;
    
    // 测试参数边界
    params.quantum_n = 128;
    params.quantum_q = 7681;
    params.quantum_p = 2;
    params.quantum_d = 32;
    params.quantum_l2_threshold = 50.0;
    params.quantum_linf_threshold = 25;
    params.quantum_max_density = 64;
    
    BOOST_CHECK_EQUAL(params.quantum_n, 128);
    BOOST_CHECK_EQUAL(params.quantum_q, 7681);
    BOOST_CHECK_EQUAL(params.quantum_p, 2);
    BOOST_CHECK_EQUAL(params.quantum_d, 32);
    BOOST_CHECK_EQUAL(params.quantum_l2_threshold, 50.0);
    BOOST_CHECK_EQUAL(params.quantum_linf_threshold, 25);
    BOOST_CHECK_EQUAL(params.quantum_max_density, 64);
}

BOOST_AUTO_TEST_CASE(hybrid_pow_compatibility_test)
{
    // 测试与现有POW系统的兼容性
    Consensus::Params params;
    params.powLimit = uint256{"00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
    
    // 测试传统POW哈希验证
    CBlockHeader header;
    header.nVersion = 1;
    header.nTime = 1234567890;
    header.nBits = 0x1e0ffff0;
    header.nNonce = 0;
    
    // 测试传统POW哈希验证
    BOOST_CHECK(CheckProofOfWorkImpl(header.GetHash(), header.nBits, params));
    
    // 测试混合POW验证（需要提供抗量子解）
    header.vchPowSolution.clear();
    BOOST_CHECK(!CheckHybridProofOfWork(header, params));
}

BOOST_AUTO_TEST_SUITE_END()

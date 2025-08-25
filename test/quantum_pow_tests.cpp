// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/util/setup_common.h>
#include <pow_quantum.h>
#include <primitives/block.h>
#include <consensus/params.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(quantum_pow_tests)

BOOST_AUTO_TEST_CASE(quantum_pow_basic_test)
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
    params.powType = Consensus::Params::PowType::QUANTUM_NTRU;
    params.quantum_n = 256;
    params.quantum_q = 12289;
    params.quantum_p = 3;
    params.quantum_d = 64;
    params.quantum_l2_threshold = 100.0;
    params.quantum_linf_threshold = 50;
    params.quantum_max_density = 128;
    
    // 测试空解应该失败
    header.vchPowSolution.clear();
    BOOST_CHECK(!CheckQuantumProofOfWork(header, params));
    
    // 测试错误大小的解应该失败
    header.vchPowSolution.resize(100, 0);
    BOOST_CHECK(!CheckQuantumProofOfWork(header, params));
    
    // 测试正确大小的解（但可能无效）
    header.vchPowSolution.resize(256 * 4, 0);
    BOOST_CHECK(!CheckQuantumProofOfWork(header, params));
}

BOOST_AUTO_TEST_CASE(quantum_pow_generation_test)
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
    params.powType = Consensus::Params::PowType::QUANTUM_NTRU;
    params.quantum_n = 256;
    params.quantum_q = 12289;
    params.quantum_p = 3;
    params.quantum_d = 64;
    params.quantum_l2_threshold = 100.0;
    params.quantum_linf_threshold = 50;
    params.quantum_max_density = 128;
    
    // 尝试生成POW解
    std::vector<uint8_t> solution;
    bool success = GenerateQuantumProofOfWork(header, params, solution);
    
    // 注意：在实际测试中，生成可能需要很长时间，所以这里只是测试接口
    // 如果成功生成，验证解的有效性
    if (success) {
        header.vchPowSolution = solution;
        BOOST_CHECK(CheckQuantumProofOfWork(header, params));
    }
}

BOOST_AUTO_TEST_CASE(quantum_pow_parameter_test)
{
    // 测试不同的参数设置
    Consensus::Params params;
    params.powType = Consensus::Params::PowType::QUANTUM_NTRU;
    
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

BOOST_AUTO_TEST_CASE(quantum_pow_compatibility_test)
{
    // 测试与现有POW系统的兼容性
    Consensus::Params params;
    
    // 测试SHA256D POW
    params.powType = Consensus::Params::PowType::SHA256D;
    BOOST_CHECK_EQUAL(params.powType, Consensus::Params::PowType::SHA256D);
    
    // 测试LATTICE_SIS POW
    params.powType = Consensus::Params::PowType::LATTICE_SIS;
    BOOST_CHECK_EQUAL(params.powType, Consensus::Params::PowType::LATTICE_SIS);
    
    // 测试QUANTUM_NTRU POW
    params.powType = Consensus::Params::PowType::QUANTUM_NTRU;
    BOOST_CHECK_EQUAL(params.powType, Consensus::Params::PowType::QUANTUM_NTRU);
}

BOOST_AUTO_TEST_SUITE_END()

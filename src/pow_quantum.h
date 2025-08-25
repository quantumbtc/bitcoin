// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POW_QUANTUM_H
#define BITCOIN_POW_QUANTUM_H

#include <consensus/params.h>
#include <primitives/block.h>
#include <vector>

/**
 * 抗量子POW算法：基于简化NTRU格密码学
 * 
 * 该算法使用多项式环上的格问题作为工作量证明的基础，
 * 对量子计算机具有抗性，同时保持与比特币协议的兼容性。
 */

/**
 * 验证抗量子POW解
 * 
 * @param[in] header    区块头
 * @param[in] params    共识参数
 * @return              true如果POW验证通过，false否则
 */
bool CheckQuantumProofOfWork(const CBlockHeader& header, const Consensus::Params& params);

/**
 * 生成抗量子POW解（挖矿）
 * 
 * @param[in] header    区块头
 * @param[in] params    共识参数
 * @param[out] solution 生成的POW解
 * @return              true如果成功生成解，false否则
 */
bool GenerateQuantumProofOfWork(const CBlockHeader& header, const Consensus::Params& params,
                               std::vector<uint8_t>& solution);

#endif // BITCOIN_POW_QUANTUM_H

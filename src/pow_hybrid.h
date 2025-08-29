// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POW_HYBRID_H
#define BITCOIN_POW_HYBRID_H

#include <consensus/params.h>
#include <primitives/block.h>

/**
 * 混合POW算法：传统哈希 + 抗量子算法
 * 
 * 该算法在保持传统比特币POW哈希验证的同时，
 * 增加抗量子算法的验证，实现双重安全保障。
 */

/** 检查混合POW：传统哈希 + 抗量子验证 */
bool CheckHybridProofOfWork(const CBlockHeader& header, const Consensus::Params& params);

/** 生成混合POW解 */
bool GenerateHybridProofOfWork(CBlock& block, const Consensus::Params& params);

void PrintHex(const std::vector<unsigned char>& data)

#endif // BITCOIN_POW_HYBRID_H

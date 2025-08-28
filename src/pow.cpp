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

// 混合POW算法：传统哈希 + 抗量子算法
#include "pow_hybrid.h"

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

// 混合POW验证：传统哈希 + 抗量子算法
bool CheckProofOfWork(const CBlockHeader& block, const Consensus::Params& params)
{
    if (EnableFuzzDeterminism()) return (block.GetHash().data()[31] & 0x80) == 0;
    
    // 第一步：验证传统比特币POW哈希
    auto bnTarget{DeriveTarget(block.nBits, params.powLimit)};
    if (!bnTarget) return false;
    
    if (!CheckProofOfWorkImpl(block.GetHash(), block.nBits, params)) {
        return false;
    }
    
    // 第二步：验证抗量子POW解
    if (!CheckHybridProofOfWork(block, params)) {
        return false;
    }
    
    return true;
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

/**
 * Check whether a difficulty transition is permitted by the consensus rules.
 * This function checks if the difficulty change from old_nbits to new_nbits
 * is within the allowed bounds for the given height.
 */
bool PermittedDifficultyTransition(const Consensus::Params& params, int height, unsigned int old_nbits, unsigned int new_nbits)
{
    // Get the old and new targets
    auto old_target = DeriveTarget(old_nbits, params.powLimit);
    auto new_target = DeriveTarget(new_nbits, params.powLimit);
    
    if (!old_target || !new_target) {
        return false;
    }
    
    // Calculate the ratio of new difficulty to old difficulty
    double ratio = static_cast<double>(new_target->getdouble()) / static_cast<double>(old_target->getdouble());
    
    // Bitcoin's difficulty adjustment rules:
    // - Difficulty can increase by at most 4x (ratio <= 0.25)
    // - Difficulty can decrease by at most 4x (ratio >= 4.0)
    // - These limits are enforced every 2016 blocks (difficulty adjustment interval)
    if (height % params.DifficultyAdjustmentInterval() == 0) {
        return ratio >= 0.25 && ratio <= 4.0;
    }
    
    // Between difficulty adjustment intervals, difficulty should not change
    return ratio == 1.0;
}

// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

/*XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
XX                                                                           XX
XX                              Optimizer                                    XX
XX                                                                           XX
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
*/

#include "jitpch.h"
#ifdef _MSC_VER
#pragma hdrstop
#endif

/*****************************************************************************/

DataFlow::DataFlow(Compiler* pCompiler)
    : m_pCompiler(pCompiler)
{
}

//------------------------------------------------------------------------
// optSetBlockWeights: adjust block weights, as follows:
// 1. Lexical block ranges where the bottom reaches the top are scaled as a loop.
//    This is a more general definition of "loop" than natural loops.
// 2. A block that is not reachable from the entry block is marked "run rarely".
// 3. If we're not using profile weights, then any block with a non-zero weight
//    that doesn't dominate all the return blocks has its weight dropped in half
//    (but only if the first block *does* dominate all the returns).
//
// Returns:
//    Suitable phase status
//
// Notes:
//    Depends on dominators, and fgReturnBlocks being set.
//
PhaseStatus Compiler::optSetBlockWeights()
{
    noway_assert(opts.OptimizationEnabled());
    assert(m_dfsTree != nullptr);

    // Leave breadcrumb for loop alignment
    fgHasLoops = m_dfsTree->HasCycle();

    // Rely on profile synthesis to propagate weights when we have PGO data.
    // TODO: Replace optSetBlockWeights with profile synthesis entirely.
    if (fgIsUsingProfileWeights())
    {
        return PhaseStatus::MODIFIED_NOTHING;
    }

    bool madeChanges = false;

    if (m_domTree == nullptr)
    {
        m_domTree = FlowGraphDominatorTree::Build(m_dfsTree);
    }
    if (m_reachabilitySets == nullptr)
    {
        m_reachabilitySets = BlockReachabilitySets::Build(m_dfsTree);
    }

    for (FlowGraphNaturalLoop* const loop : m_loops->InReversePostOrder())
    {
        optScaleLoopBlocks(loop);
        madeChanges = true;
    }

    bool firstBBDominatesAllReturns = true;

    fgComputeReturnBlocks();

    // TODO-Quirk: Previously, this code ran on a dominator tree based only on
    // regular flow. This meant that all handlers were not considered to be
    // dominated by fgFirstBB. When those handlers could reach a return
    // block that return was also not considered to be dominated by fgFirstBB.
    // In practice the code below would then not make any changes for those
    // functions. We emulate that behavior here.
    for (EHblkDsc* eh : EHClauses(this))
    {
        BasicBlock* flowBlock = eh->ExFlowBlock();

        for (BasicBlockList* retBlocks = fgReturnBlocks; retBlocks != nullptr; retBlocks = retBlocks->next)
        {
            if (m_dfsTree->Contains(flowBlock) && m_reachabilitySets->CanReach(flowBlock, retBlocks->block))
            {
                firstBBDominatesAllReturns = false;
                break;
            }
        }

        if (!firstBBDominatesAllReturns)
        {
            break;
        }
    }

    for (BasicBlock* const block : Blocks())
    {
        // Blocks that can't be reached via the first block are rarely executed
        if (!m_reachabilitySets->CanReach(fgFirstBB, block) && !block->isRunRarely() && !block->hasProfileWeight())
        {
            madeChanges = true;
            block->bbSetRunRarely();
        }

        if (firstBBDominatesAllReturns)
        {
            // If the weight is already zero (and thus rarely run), there's no point scaling it.
            if (block->bbWeight != BB_ZERO_WEIGHT)
            {
                // If the block dominates all return blocks, leave the weight alone. Otherwise,
                // scale the weight by 0.5 as a heuristic that some other path gets some of the dynamic flow.
                // Note that `optScaleLoopBlocks` has a similar heuristic for loop blocks that don't dominate
                // their loop back edge.

                bool blockDominatesAllReturns = true; // Assume that we will dominate

                for (BasicBlockList* retBlocks = fgReturnBlocks; retBlocks != nullptr; retBlocks = retBlocks->next)
                {
                    // TODO-Quirk: Returns that are unreachable can just be ignored.
                    if (!m_dfsTree->Contains(retBlocks->block) || !m_domTree->Dominates(block, retBlocks->block))
                    {
                        blockDominatesAllReturns = false;
                        break;
                    }
                }

                if (block == fgFirstBB)
                {
                    firstBBDominatesAllReturns = blockDominatesAllReturns;

                    // Don't scale the weight of the first block, since it is guaranteed to execute.
                    // If the first block does not dominate all the returns, we won't scale any of the function's
                    // block weights.
                }
                else
                {
                    // If we are not using profile weight then we lower the weight
                    // of blocks that do not dominate a return block
                    //
                    if (!blockDominatesAllReturns)
                    {
                        madeChanges = true;

                        // TODO-Cleanup: we should use:
                        //    block->scaleBBWeight(0.5);
                        // since we are inheriting "from ourselves", but that leads to asm diffs due to minutely
                        // different floating-point value in the calculation, and some code that compares weights
                        // for equality.
                        block->inheritWeightPercentage(block, 50);
                    }
                }
            }
        }
    }

    return madeChanges ? PhaseStatus::MODIFIED_EVERYTHING : PhaseStatus::MODIFIED_NOTHING;
}

//------------------------------------------------------------------------
// optScaleLoopBlocks: Scale the weight of the blocks in 'loop'.
//
// Arguments:
//      loop - the loop to scale the weight of.
//
// Operation:
//      Calculate the 'loop weight'. This is the amount to scale the weight of each block in the loop.
//      Our heuristic is that loops are weighted eight times more than straight-line code
//      (scale factor is BB_LOOP_WEIGHT_SCALE). If the loops are all properly formed this gives us these weights:
//
//          1 -- non-loop basic block
//          8 -- single loop nesting
//         64 -- double loop nesting
//        512 -- triple loop nesting
//
void Compiler::optScaleLoopBlocks(FlowGraphNaturalLoop* loop)
{
    loop->VisitLoopBlocks([&](BasicBlock* curBlk) -> BasicBlockVisit {
        auto reportBlockWeight = [&](const char* message) {
            DBEXEC(verbose,
                   printf("\n    " FMT_BB "(wt=" FMT_WT ")%s", curBlk->bbNum, curBlk->getBBWeight(this), message));
        };

        // Don't change the block weight if it came from profile data.
        if (curBlk->hasProfileWeight() && fgHaveProfileWeights())
        {
            reportBlockWeight("; unchanged: has profile weight");
            return BasicBlockVisit::Continue;
        }

        // Don't change the block weight if it's known to be rarely run.
        if (curBlk->isRunRarely())
        {
            reportBlockWeight("; unchanged: run rarely");
            return BasicBlockVisit::Continue;
        }

        // If `curBlk` dominates any of the back edge blocks we set `dominates`.
        bool dominates = false;

        for (FlowEdge* const backEdge : loop->BackEdges())
        {
            BasicBlock* const backEdgeSource = backEdge->getSourceBlock();
            dominates |= m_domTree->Dominates(curBlk, backEdgeSource);

            if (dominates)
            {
                // No need to keep looking; we've already found all the info we need.
                break;
            }
        }

        weight_t scale = BB_LOOP_WEIGHT_SCALE;

        if (!dominates)
        {
            // If `curBlk` reaches but doesn't dominate any back edge to `endBlk` then there must be at least
            // some other path to `endBlk`, so don't give `curBlk` all the execution weight.
            scale = scale / 2;
        }

        curBlk->scaleBBWeight(scale);

        reportBlockWeight("");

        return BasicBlockVisit::Continue;
    });
}

//----------------------------------------------------------------------------------
// optIsLoopIncrTree: Check if loop is a tree of form v = v op const.
//
// Arguments:
//      incr - The incr tree to be checked.
//
//  Return Value:
//      iterVar local num if the iterVar is found, otherwise BAD_VAR_NUM.
//
unsigned Compiler::optIsLoopIncrTree(GenTree* incr)
{
    GenTree*   incrVal;
    genTreeOps updateOper;
    unsigned   iterVar = incr->IsLclVarUpdateTree(&incrVal, &updateOper);
    if (iterVar != BAD_VAR_NUM)
    {
        // We have v = v op y type node.
        switch (updateOper)
        {
            case GT_ADD:
            case GT_SUB:
            case GT_MUL:
            case GT_RSH:
            case GT_LSH:
                break;
            default:
                return BAD_VAR_NUM;
        }

        // Increment should be by a const int.
        // TODO-CQ: CLONE: allow variable increments.
        if (!incrVal->OperIs(GT_CNS_INT) || !incrVal->TypeIs(TYP_INT))
        {
            return BAD_VAR_NUM;
        }
    }

    return iterVar;
}

//----------------------------------------------------------------------------------
// optIsLoopTestEvalIntoTemp:
//      Pattern match if the test tree is computed into a tmp
//      and the "tmp" is used as jump condition for loop termination.
//
// Arguments:
//      testStmt    - is the JTRUE statement that is of the form: jmpTrue (Vtmp != 0)
//                    where Vtmp contains the actual loop test result.
//      newTestStmt - contains the statement that is the actual test stmt involving
//                    the loop iterator.
//
//  Return Value:
//      Returns true if a new test tree can be obtained.
//
//  Operation:
//      Scan if the current stmt is a jtrue with (Vtmp != 0) as condition
//      Then returns the rhs for def of Vtmp as the "test" node.
//
//  Note:
//      This method just retrieves what it thinks is the "test" node,
//      the callers are expected to verify that "iterVar" is used in the test.
//
bool Compiler::optIsLoopTestEvalIntoTemp(Statement* testStmt, Statement** newTestStmt)
{
    GenTree* test = testStmt->GetRootNode();

    if (!test->OperIs(GT_JTRUE))
    {
        return false;
    }

    GenTree* relop = test->gtGetOp1();
    noway_assert(relop->OperIsCompare());

    GenTree* opr1 = relop->AsOp()->gtOp1;
    GenTree* opr2 = relop->AsOp()->gtOp2;

    // Make sure we have jtrue (vtmp != 0)
    if (relop->OperIs(GT_NE) && opr1->OperIs(GT_LCL_VAR) && opr2->OperIs(GT_CNS_INT) && opr2->IsIntegralConst(0))
    {
        // Get the previous statement to get the def (rhs) of Vtmp to see
        // if the "test" is evaluated into Vtmp.
        Statement* prevStmt = testStmt->GetPrevStmt();
        if (prevStmt == nullptr)
        {
            return false;
        }

        GenTree* tree = prevStmt->GetRootNode();
        if (tree->OperIs(GT_STORE_LCL_VAR) && (tree->AsLclVar()->GetLclNum() == opr1->AsLclVar()->GetLclNum()) &&
            tree->AsLclVar()->Data()->OperIsCompare())
        {
            *newTestStmt = prevStmt;
            return true;
        }
    }
    return false;
}

//----------------------------------------------------------------------------------
// optExtractInitTestIncr:
//      Extract the "init", "test" and "incr" nodes of the loop.
//
// Arguments:
//      pInitBlock - [IN/OUT] *pInitBlock is the loop head block on entry, and is set to the initBlock on exit,
//                   if `**ppInit` is non-null.
//      cond       - A BBJ_COND block that exits the loop
//      header     - Loop header block
//      ppInit     - [out] The init stmt of the loop if found.
//      ppTest     - [out] The test stmt of the loop if found.
//      ppIncr     - [out] The incr stmt of the loop if found.
//
//  Return Value:
//      The results are put in "ppInit", "ppTest" and "ppIncr" if the method
//      returns true. Returns false if the information can't be extracted.
//      Extracting the `init` is optional; if one is not found, *ppInit is set
//      to nullptr. Return value will never be false if `init` is not found.
//
//  Operation:
//      Check if the "test" stmt is last stmt in an exiting BBJ_COND block of the loop. Try to find the "incr" stmt.
//      Check previous stmt of "test" to get the "incr" stmt.
//
//  Note:
//      This method just retrieves what it thinks is the "test" node,
//      the callers are expected to verify that "iterVar" is used in the test.
//
bool Compiler::optExtractInitTestIncr(
    BasicBlock** pInitBlock, BasicBlock* cond, BasicBlock* header, GenTree** ppInit, GenTree** ppTest, GenTree** ppIncr)
{
    assert(pInitBlock != nullptr);
    assert(ppInit != nullptr);
    assert(ppTest != nullptr);
    assert(ppIncr != nullptr);

    // Check if last two statements in the loop body are the increment of the iterator
    // and the loop termination test.
    noway_assert(cond->bbStmtList != nullptr);
    Statement* testStmt = cond->lastStmt();
    noway_assert(testStmt != nullptr && testStmt->GetNextStmt() == nullptr);

    Statement* newTestStmt;
    if (optIsLoopTestEvalIntoTemp(testStmt, &newTestStmt))
    {
        testStmt = newTestStmt;
    }

    // Check if we have the incr stmt before the test stmt, if we don't,
    // check if incr is part of the loop "header".
    Statement* incrStmt = testStmt->GetPrevStmt();

    // If we've added profile instrumentation, we may need to skip past a BB counter update.
    //
    if (opts.jitFlags->IsSet(JitFlags::JIT_FLAG_BBINSTR) && (incrStmt != nullptr) &&
        incrStmt->GetRootNode()->IsBlockProfileUpdate())
    {
        incrStmt = incrStmt->GetPrevStmt();
    }

    if (incrStmt == nullptr || (optIsLoopIncrTree(incrStmt->GetRootNode()) == BAD_VAR_NUM))
    {
        return false;
    }

    assert(testStmt != incrStmt);

    // Find the last statement in the loop pre-header which we expect to be the initialization of
    // the loop iterator.
    BasicBlock* initBlock = *pInitBlock;
    Statement*  phdrStmt  = initBlock->firstStmt();
    if (phdrStmt == nullptr)
    {
        // When we build the loops, we canonicalize by introducing loop pre-headers for all loops.
        // If we are rebuilding the loops, we would already have the pre-header block introduced
        // the first time, which might be empty if no hoisting has yet occurred. In this case, look a
        // little harder for the possible loop initialization statement.
        if (initBlock->KindIs(BBJ_ALWAYS) && initBlock->TargetIs(header))
        {
            BasicBlock* uniquePred = initBlock->GetUniquePred(this);
            if (uniquePred != nullptr)
            {
                initBlock = uniquePred;
                phdrStmt  = initBlock->firstStmt();
            }
        }
    }

    if (phdrStmt != nullptr)
    {
        Statement* initStmt = phdrStmt->GetPrevStmt();
        noway_assert(initStmt != nullptr && (initStmt->GetNextStmt() == nullptr));

        // If it is a duplicated loop condition, skip it.
        if (initStmt->GetRootNode()->OperIs(GT_JTRUE))
        {
            bool doGetPrev = true;
            if (opts.optRepeat)
            {
                // Previous optimization passes may have inserted compiler-generated
                // statements other than duplicated loop conditions.
                doGetPrev = (initStmt->GetPrevStmt() != nullptr);
            }
            if (doGetPrev)
            {
                initStmt = initStmt->GetPrevStmt();
            }
            noway_assert(initStmt != nullptr);
        }

        *ppInit     = initStmt->GetRootNode();
        *pInitBlock = initBlock;
    }
    else
    {
        *ppInit = nullptr;
    }

    *ppTest = testStmt->GetRootNode();
    *ppIncr = incrStmt->GetRootNode();

    return true;
}

#ifdef DEBUG
void Compiler::optCheckPreds()
{
    for (BasicBlock* const block : Blocks())
    {
        for (BasicBlock* const predBlock : block->PredBlocks())
        {
            // make sure this pred is part of the BB list
            BasicBlock* bb;
            for (bb = fgFirstBB; bb; bb = bb->Next())
            {
                if (bb == predBlock)
                {
                    break;
                }
            }
            noway_assert(bb);
            switch (bb->GetKind())
            {
                case BBJ_COND:
                    if (bb->TrueTargetIs(block))
                    {
                        break;
                    }
                    noway_assert(bb->FalseTargetIs(block));
                    break;
                case BBJ_EHFILTERRET:
                case BBJ_ALWAYS:
                case BBJ_EHCATCHRET:
                    noway_assert(bb->TargetIs(block));
                    break;
                default:
                    break;
            }
        }
    }
}

#endif // DEBUG

//------------------------------------------------------------------------
// optSetMappedBlockTargets: Initialize the branch successors of a block based on a block map.
//
// Updates the successors of `newBlk`, a copy of `blk`:
// If `blk2` is a branch successor of `blk`, and there is a mapping
// for `blk2->blk3` in `redirectMap`, make `blk3` a successor of `newBlk`.
// Else, make `blk2` a successor of `newBlk`.
//
// Arguments:
//     blk          - the original block, which doesn't need redirecting
//     newBlk       - copy of blk, with uninitialized successors
//     redirectMap  - block->block map specifying how to redirect the target of `blk`.
//
// Notes:
//     Initially, `newBlk` should not have any successors set.
//     Upon returning, `newBlk` should have all of its successors initialized.
//     `blk` must have its successors set upon entry; these won't be changed.
//
void Compiler::optSetMappedBlockTargets(BasicBlock* blk, BasicBlock* newBlk, BlockToBlockMap* redirectMap)
{
    // Caller should not have initialized newBlk's target yet
    assert(newBlk->KindIs(BBJ_ALWAYS));
    assert(!newBlk->HasInitializedTarget());

    BasicBlock* newTarget;

    // Initialize the successors of "newBlk".
    // For each successor, use "blockMap" to determine if the successor needs to be redirected.
    switch (blk->GetKind())
    {
        case BBJ_ALWAYS:
        case BBJ_CALLFINALLY:
        case BBJ_CALLFINALLYRET:
        case BBJ_LEAVE:
        case BBJ_EHCATCHRET:
        case BBJ_EHFILTERRET:
        {
            FlowEdge* newEdge;

            // Determine if newBlk should be redirected to a different target from blk's target
            if (redirectMap->Lookup(blk->GetTarget(), &newTarget))
            {
                // newBlk needs to be redirected to a new target
                newEdge = fgAddRefPred(newTarget, newBlk);
            }
            else
            {
                // newBlk uses the same target as blk
                newEdge = fgAddRefPred(blk->GetTarget(), newBlk);
            }

            newBlk->SetKindAndTargetEdge(blk->GetKind(), newEdge);
            break;
        }

        case BBJ_COND:
        {
            BasicBlock* trueTarget;
            BasicBlock* falseTarget;

            // Determine if newBLk should be redirected to a different true target from blk's true target
            if (redirectMap->Lookup(blk->GetTrueTarget(), &newTarget))
            {
                // newBlk needs to be redirected to a new true target
                trueTarget = newTarget;
            }
            else
            {
                // newBlk uses the same true target as blk
                trueTarget = blk->GetTrueTarget();
            }

            // Do the same lookup for the false target
            if (redirectMap->Lookup(blk->GetFalseTarget(), &newTarget))
            {
                falseTarget = newTarget;
            }
            else
            {
                falseTarget = blk->GetFalseTarget();
            }

            FlowEdge* const oldTrueEdge  = blk->GetTrueEdge();
            FlowEdge* const trueEdge     = fgAddRefPred(trueTarget, newBlk, oldTrueEdge);
            FlowEdge* const oldFalseEdge = blk->GetFalseEdge();
            FlowEdge* const falseEdge    = fgAddRefPred(falseTarget, newBlk, oldFalseEdge);
            newBlk->SetCond(trueEdge, falseEdge);
            break;
        }

        case BBJ_EHFINALLYRET:
        {
            BBJumpTable* currEhfDesc = blk->GetEhfTargets();
            FlowEdge**   newSuccs    = new (this, CMK_FlowEdge) FlowEdge*[currEhfDesc->GetSuccCount()];

            for (unsigned i = 0; i < currEhfDesc->GetSuccCount(); i++)
            {
                FlowEdge* const   inspiringEdge = currEhfDesc->GetSucc(i);
                BasicBlock* const ehfTarget     = inspiringEdge->getDestinationBlock();
                FlowEdge*         newEdge;

                // Determine if newBlk should target ehfTarget, or be redirected
                if (redirectMap->Lookup(ehfTarget, &newTarget))
                {
                    newEdge = fgAddRefPred(newTarget, newBlk, inspiringEdge);
                }
                else
                {
                    newEdge = fgAddRefPred(ehfTarget, newBlk, inspiringEdge);
                }

                newSuccs[i] = newEdge;
            }

            BBJumpTable* newEhfDesc = new (this, CMK_BasicBlock) BBJumpTable(newSuccs, currEhfDesc->GetSuccCount());
            newBlk->SetEhf(newEhfDesc);
            break;
        }

        case BBJ_SWITCH:
        {
            BBswtDesc* currSwtDesc = blk->GetSwitchTargets();
            BBswtDesc* newSwtDesc  = new (this, CMK_BasicBlock) BBswtDesc(this, currSwtDesc);
            FlowEdge** succPtr     = newSwtDesc->GetSuccs();

            for (unsigned i = 0; i < newSwtDesc->GetCaseCount(); i++)
            {
                FlowEdge* const   inspiringEdge = currSwtDesc->GetCase(i);
                BasicBlock* const switchTarget  = inspiringEdge->getDestinationBlock();
                FlowEdge*         newEdge;

                // Determine if newBlk should target switchTarget, or be redirected
                if (redirectMap->Lookup(switchTarget, &newTarget))
                {
                    newEdge = fgAddRefPred(newTarget, newBlk);
                }
                else
                {
                    newEdge = fgAddRefPred(switchTarget, newBlk);
                }

                // Transfer likelihood... instead of doing this gradually
                // for dup'd edges, we set it once, when we add the last dup.
                // Also, add the new edge to the unique successor table.
                //
                if (newEdge->getDupCount() == inspiringEdge->getDupCount())
                {
                    newEdge->setLikelihood(inspiringEdge->getLikelihood());
                    *succPtr = newEdge;
                    succPtr++;
                }

                newSwtDesc->GetCases()[i] = newEdge;
            }

            newBlk->SetSwitch(newSwtDesc);
            break;
        }

        default:
            // blk doesn't have a jump destination
            assert(blk->NumSucc() == 0);
            newBlk->SetKindAndTargetEdge(blk->GetKind());
            break;
    }

    assert(newBlk->KindIs(blk->GetKind()));
}

//-----------------------------------------------------------------------------
// optIterSmallOverflow: Helper for loop unrolling. Determine if "i += const" will
// cause an overflow exception for the small types.
//
// Arguments:
//    iterAtExit - iteration constant at loop exit
//    incrType   - type of increment
//
// Returns:
//   true if overflow
//
// static
bool Compiler::optIterSmallOverflow(int iterAtExit, var_types incrType)
{
    int type_MAX;

    switch (incrType)
    {
        case TYP_BYTE:
            type_MAX = SCHAR_MAX;
            break;
        case TYP_UBYTE:
            type_MAX = UCHAR_MAX;
            break;
        case TYP_SHORT:
            type_MAX = SHRT_MAX;
            break;
        case TYP_USHORT:
            type_MAX = USHRT_MAX;
            break;

        case TYP_UINT: // Detected by checking for 32bit ....
        case TYP_INT:
            return false; // ... overflow same as done for TYP_INT

        default:
            NO_WAY("Bad type");
    }

    if (iterAtExit > type_MAX)
    {
        return true;
    }
    else
    {
        return false;
    }
}

//-----------------------------------------------------------------------------
// optIterSmallUnderflow: Helper for loop unrolling. Determine if "i -= const" will
// cause an underflow exception for the small types.
//
// Arguments:
//    iterAtExit - iteration constant at loop exit
//    decrType   - type of decrement
//
// Returns:
//   true if overflow
//
// static
bool Compiler::optIterSmallUnderflow(int iterAtExit, var_types decrType)
{
    int type_MIN;

    switch (decrType)
    {
        case TYP_BYTE:
            type_MIN = SCHAR_MIN;
            break;
        case TYP_SHORT:
            type_MIN = SHRT_MIN;
            break;
        case TYP_UBYTE:
            type_MIN = 0;
            break;
        case TYP_USHORT:
            type_MIN = 0;
            break;

        case TYP_UINT: // Detected by checking for 32bit ....
        case TYP_INT:
            return false; // ... underflow same as done for TYP_INT

        default:
            NO_WAY("Bad type");
    }

    if (iterAtExit < type_MIN)
    {
        return true;
    }
    else
    {
        return false;
    }
}

//-----------------------------------------------------------------------------
// optComputeLoopRep: Helper for loop unrolling. Computes the number of times
// the test block of a loop is executed.
//
// Arguments:
//    constInit     - loop constant initial value
//    constLimit    - loop constant limit
//    iterInc       - loop iteration increment
//    iterOper      - loop iteration increment operator (ADD, SUB, etc.)
//    iterOperType  - iteration operator type
//    testOper      - type of loop test (i.e. GT_LE, GT_GE, etc.)
//    unsTest       - true if test is unsigned
//    iterCount     - *iterCount is set to the iteration count, if the function returns `true`
//
// Returns:
//   true if the loop has a constant repetition count, false if that cannot be proven
//
bool Compiler::optComputeLoopRep(int        constInit,
                                 int        constLimit,
                                 int        iterInc,
                                 genTreeOps iterOper,
                                 var_types  iterOperType,
                                 genTreeOps testOper,
                                 bool       unsTest,
                                 unsigned*  iterCount)
{
    noway_assert(genActualType(iterOperType) == TYP_INT);

    int64_t constInitX;
    int64_t constLimitX;

    unsigned loopCount;
    int      iterSign;

    // Using this, we can just do a signed comparison with other 32 bit values.
    if (unsTest)
    {
        constLimitX = (unsigned int)constLimit;
    }
    else
    {
        constLimitX = (signed int)constLimit;
    }

    switch (iterOperType)
    {
        // For small types, the iteration operator will narrow these values if big

#define INIT_ITER_BY_TYPE(type)                                                                                        \
    constInitX = (type)constInit;                                                                                      \
    iterInc    = (type)iterInc;

        case TYP_BYTE:
            INIT_ITER_BY_TYPE(signed char);
            break;
        case TYP_UBYTE:
            INIT_ITER_BY_TYPE(unsigned char);
            break;
        case TYP_SHORT:
            INIT_ITER_BY_TYPE(signed short);
            break;
        case TYP_USHORT:
            INIT_ITER_BY_TYPE(unsigned short);
            break;

            // For the big types, 32 bit arithmetic is performed

        case TYP_INT:
            if (unsTest)
            {
                constInitX = (unsigned int)constInit;
            }
            else
            {
                constInitX = (signed int)constInit;
            }
            break;

        default:
            noway_assert(!"Bad type");
            NO_WAY("Bad type");
    }

    // If iterInc is zero we have an infinite loop.
    if (iterInc == 0)
    {
        return false;
    }

    iterSign  = (iterInc > 0) ? +1 : -1;
    loopCount = 0;

    // bail if count is based on wrap-around math
    if (iterInc > 0)
    {
        if (constLimitX < constInitX)
        {
            return false;
        }
    }
    else if (constLimitX > constInitX)
    {
        return false;
    }

    // Compute the number of repetitions.

    switch (testOper)
    {
        int64_t iterAtExitX;

        case GT_EQ:
            // Something like "for (i=init; i == lim; i++)" doesn't make any sense.
            return false;

        case GT_NE:
            // Consider: "for (i = init; i != lim; i += const)"
            // This is tricky since it may have a constant number of iterations or loop forever.
            // We have to compute "(lim - init) mod iterInc" to see if it is zero.
            // If "mod iterInc" is not zero then the limit test will miss and a wrap will occur
            // which is probably not what the end user wanted, but it is legal.

            if (iterInc > 0)
            {
                // Stepping by one, i.e. Mod with 1 is always zero.
                if (iterInc != 1)
                {
                    if (((constLimitX - constInitX) % iterInc) != 0)
                    {
                        return false;
                    }
                }
            }
            else
            {
                // Stepping by -1, i.e. Mod with 1 is always zero.
                if (iterInc != -1)
                {
                    if (((constInitX - constLimitX) % (-iterInc)) != 0)
                    {
                        return false;
                    }
                }
            }

            switch (iterOper)
            {
                case GT_SUB:
                    iterInc = -iterInc;
                    FALLTHROUGH;

                case GT_ADD:
                    if (constInitX != constLimitX)
                    {
                        loopCount += (unsigned)((constLimitX - constInitX - iterSign) / iterInc) + 1;
                    }

                    iterAtExitX = (int)(constInitX + iterInc * (int)loopCount);

                    if (unsTest)
                    {
                        iterAtExitX = (unsigned)iterAtExitX;
                    }

                    // Check if iteration incr will cause overflow for small types
                    if (optIterSmallOverflow((int)iterAtExitX, iterOperType))
                    {
                        return false;
                    }

                    // iterator with 32bit overflow. Bad for TYP_(U)INT
                    if (iterAtExitX < constLimitX)
                    {
                        return false;
                    }

                    *iterCount = loopCount;
                    return true;

                case GT_MUL:
                case GT_DIV:
                case GT_RSH:
                case GT_LSH:
                case GT_UDIV:
                    return false;

                default:
                    noway_assert(!"Unknown operator for loop iterator");
                    return false;
            }

        case GT_LT:
            switch (iterOper)
            {
                case GT_SUB:
                    iterInc = -iterInc;
                    FALLTHROUGH;

                case GT_ADD:
                    if (constInitX < constLimitX)
                    {
                        loopCount += (unsigned)((constLimitX - constInitX - iterSign) / iterInc) + 1;
                    }

                    iterAtExitX = (int)(constInitX + iterInc * (int)loopCount);

                    if (unsTest)
                    {
                        iterAtExitX = (unsigned)iterAtExitX;
                    }

                    // Check if iteration incr will cause overflow for small types
                    if (optIterSmallOverflow((int)iterAtExitX, iterOperType))
                    {
                        return false;
                    }

                    // iterator with 32bit overflow. Bad for TYP_(U)INT
                    if (iterAtExitX < constLimitX)
                    {
                        return false;
                    }

                    *iterCount = loopCount;
                    return true;

                case GT_MUL:
                case GT_DIV:
                case GT_RSH:
                case GT_LSH:
                case GT_UDIV:
                    return false;

                default:
                    noway_assert(!"Unknown operator for loop iterator");
                    return false;
            }

        case GT_LE:
            switch (iterOper)
            {
                case GT_SUB:
                    iterInc = -iterInc;
                    FALLTHROUGH;

                case GT_ADD:
                    if (constInitX <= constLimitX)
                    {
                        loopCount += (unsigned)((constLimitX - constInitX) / iterInc) + 1;
                    }

                    iterAtExitX = (int)(constInitX + iterInc * (int)loopCount);

                    if (unsTest)
                    {
                        iterAtExitX = (unsigned)iterAtExitX;
                    }

                    // Check if iteration incr will cause overflow for small types
                    if (optIterSmallOverflow((int)iterAtExitX, iterOperType))
                    {
                        return false;
                    }

                    // iterator with 32bit overflow. Bad for TYP_(U)INT
                    if (iterAtExitX <= constLimitX)
                    {
                        return false;
                    }

                    *iterCount = loopCount;
                    return true;

                case GT_MUL:
                case GT_DIV:
                case GT_RSH:
                case GT_LSH:
                case GT_UDIV:
                    return false;

                default:
                    noway_assert(!"Unknown operator for loop iterator");
                    return false;
            }

        case GT_GT:
            switch (iterOper)
            {
                case GT_SUB:
                    iterInc = -iterInc;
                    FALLTHROUGH;

                case GT_ADD:
                    if (constInitX > constLimitX)
                    {
                        loopCount += (unsigned)((constLimitX - constInitX - iterSign) / iterInc) + 1;
                    }

                    iterAtExitX = (int)(constInitX + iterInc * (int)loopCount);

                    if (unsTest)
                    {
                        iterAtExitX = (unsigned)iterAtExitX;
                    }

                    // Check if small types will underflow
                    if (optIterSmallUnderflow((int)iterAtExitX, iterOperType))
                    {
                        return false;
                    }

                    // iterator with 32bit underflow. Bad for TYP_INT and unsigneds
                    if (iterAtExitX > constLimitX)
                    {
                        return false;
                    }

                    *iterCount = loopCount;
                    return true;

                case GT_MUL:
                case GT_DIV:
                case GT_RSH:
                case GT_LSH:
                case GT_UDIV:
                    return false;

                default:
                    noway_assert(!"Unknown operator for loop iterator");
                    return false;
            }

        case GT_GE:
            switch (iterOper)
            {
                case GT_SUB:
                    iterInc = -iterInc;
                    FALLTHROUGH;

                case GT_ADD:
                    if (constInitX >= constLimitX)
                    {
                        loopCount += (unsigned)((constLimitX - constInitX) / iterInc) + 1;
                    }

                    iterAtExitX = (int)(constInitX + iterInc * (int)loopCount);

                    if (unsTest)
                    {
                        iterAtExitX = (unsigned)iterAtExitX;
                    }

                    // Check if small types will underflow
                    if (optIterSmallUnderflow((int)iterAtExitX, iterOperType))
                    {
                        return false;
                    }

                    // iterator with 32bit underflow. Bad for TYP_INT and unsigneds
                    if (iterAtExitX >= constLimitX)
                    {
                        return false;
                    }

                    *iterCount = loopCount;
                    return true;

                case GT_MUL:
                case GT_DIV:
                case GT_RSH:
                case GT_LSH:
                case GT_UDIV:
                    return false;

                default:
                    noway_assert(!"Unknown operator for loop iterator");
                    return false;
            }

        default:
            noway_assert(!"Unknown operator for loop condition");
    }

    return false;
}

//-----------------------------------------------------------------------------
// optUnrollLoops: Look for loop unrolling candidates and unroll them.
//
// Loops must be of the form:
//   for (i=icon; i<icon; i++) { ... }
//
// Loops handled are fully unrolled; there is no partial unrolling.
//
// Limitations: only the following loop types are handled:
// 1. constant initializer, constant bound
// 2. The entire loop must be in the same EH region.
// 3. The loop iteration variable can't be address exposed.
// 4. The loop iteration variable can't be a promoted struct field.
// 5. We must be able to calculate the total constant iteration count.
//
// Cost heuristics:
// 1. there are cost metrics for maximum number of allowed iterations, and maximum unroll size
// 2. constant trip count loops are always allowed, up to a limit of 4
// 3. otherwise, only loops where the limit is Vector<T>.Length are currently allowed
//
// In stress modes, these heuristic limits are expanded, and loops aren't required to have the
// Vector<T>.Length limit.
//
// Loops are processed from innermost to outermost order, to attempt to unroll the most nested loops first.
//
// Returns:
//   suitable phase status
//
PhaseStatus Compiler::optUnrollLoops()
{
    if (compCodeOpt() == SMALL_CODE)
    {
        return PhaseStatus::MODIFIED_NOTHING;
    }

    if (m_loops->NumLoops() == 0)
    {
        return PhaseStatus::MODIFIED_NOTHING;
    }

#ifdef DEBUG
    if (JitConfig.JitNoUnroll())
    {
        return PhaseStatus::MODIFIED_NOTHING;
    }
#endif

    // Look for loop unrolling candidates

    int  unrollCount = 0;
    bool anyIRchange = false;

    int passes = 0;

    while (true)
    {
        // We track loops for which we unrolled a descendant loop. Since unrolling
        // introduces/removes blocks, we retry unrolling for the parent loops
        // separately, to avoid having to maintain the removed/added blocks.
        BitVecTraits loopTraits((unsigned)m_loops->NumLoops(), this);
        BitVec       loopsWithUnrolledDescendant(BitVecOps::MakeEmpty(&loopTraits));

        // Visit loops in post order (inner loops before outer loops).
        for (FlowGraphNaturalLoop* loop : m_loops->InPostOrder())
        {
            if (BitVecOps::IsMember(&loopTraits, loopsWithUnrolledDescendant, loop->GetIndex()))
            {
                continue;
            }

            if (!optTryUnrollLoop(loop, &anyIRchange))
            {
                continue;
            }

            unrollCount++;

            // Mark in all ancestors now that one of their descendant loops was
            // unrolled to indicate that the set of loop blocks changed.
            for (FlowGraphNaturalLoop* ancestor = loop->GetParent(); ancestor != nullptr;
                 ancestor                       = ancestor->GetParent())
            {
                BitVecOps::AddElemD(&loopTraits, loopsWithUnrolledDescendant, ancestor->GetIndex());
            }
        }

        if ((unrollCount == 0) || BitVecOps::IsEmpty(&loopTraits, loopsWithUnrolledDescendant) || (passes >= 10))
        {
            break;
        }

        JITDUMP("A nested loop was unrolled. Doing another pass (pass %d)\n", passes + 1);
        fgInvalidateDfsTree();
        m_dfsTree = fgComputeDfs();
        m_loops   = FlowGraphNaturalLoops::Find(m_dfsTree);
        passes++;
    }

    if (unrollCount > 0)
    {
        assert(anyIRchange);

        Metrics.LoopsUnrolled += unrollCount;

#ifdef DEBUG
        if (verbose)
        {
            printf("\nFinished unrolling %d loops in %d passes", unrollCount, passes);
            printf("\n");
        }
#endif // DEBUG

        // We left the old loops unreachable as part of unrolling, so get rid of
        // those blocks now.
        fgDfsBlocksAndRemove();
        m_loops = FlowGraphNaturalLoops::Find(m_dfsTree);

        if (optCanonicalizeLoops())
        {
            fgInvalidateDfsTree();
            m_dfsTree = fgComputeDfs();
            m_loops   = FlowGraphNaturalLoops::Find(m_dfsTree);
        }

        DBEXEC(verbose, fgDispBasicBlocks());
    }

#ifdef DEBUG
    fgDebugCheckBBlist();
#endif // DEBUG

    return anyIRchange ? PhaseStatus::MODIFIED_EVERYTHING : PhaseStatus::MODIFIED_NOTHING;
}

//-----------------------------------------------------------------------------
// optTryUnrollLoop: Do legality and profitability checks and try to unroll a
// single loop.
//
// Parameters:
//   loop      - The loop to try unrolling
//   changedIR - [out] Whether or not the IR was changed. Can be true even if
//               the function returns false.
//
// Returns:
//   True if the loop was unrolled, in which case the flow graph was changed.
//
bool Compiler::optTryUnrollLoop(FlowGraphNaturalLoop* loop, bool* changedIR)
{
    static const unsigned ITER_LIMIT[COUNT_OPT_CODE + 1] = {
        10, // BLENDED_CODE
        0,  // SMALL_CODE
        20, // FAST_CODE
        0   // COUNT_OPT_CODE
    };

    assert(ITER_LIMIT[SMALL_CODE] == 0);
    assert(ITER_LIMIT[COUNT_OPT_CODE] == 0);

    unsigned iterLimit = ITER_LIMIT[compCodeOpt()];

#ifdef DEBUG
    if (compStressCompile(STRESS_UNROLL_LOOPS, 50))
    {
        iterLimit *= 10;
    }
#endif

    static const int UNROLL_LIMIT_SZ[COUNT_OPT_CODE + 1] = {
        300, // BLENDED_CODE
        0,   // SMALL_CODE
        600, // FAST_CODE
        0    // COUNT_OPT_CODE
    };

    assert(UNROLL_LIMIT_SZ[SMALL_CODE] == 0);
    assert(UNROLL_LIMIT_SZ[COUNT_OPT_CODE] == 0);

    if (loop->GetHeader()->isRunRarely())
    {
        JITDUMP("Failed to unroll loop " FMT_LP ": Loop is cold.\n", loop->GetIndex());
        return false;
    }

    NaturalLoopIterInfo iterInfo;
    if (!loop->AnalyzeIteration(&iterInfo))
    {
        return false;
    }

    // Check for required flags:
    // HasConstInit  - required because this transform only handles full unrolls
    // HasConstLimit - required because this transform only handles full unrolls
    if (!iterInfo.HasConstInit || !iterInfo.HasConstLimit)
    {
        // Don't print to the JitDump about this common case.
        return false;
    }

    // The loop test must be both an exit and a backedge.
    // FlowGraphNaturalLoop::AnalyzeIteration ensures it is an exit but we must
    // make sure it is a backedge so that we can legally redirect it to the
    // next iteration. If it isn't a backedge then redirecting it would skip
    // all code between the loop test and the backedge.
    assert(loop->ContainsBlock(iterInfo.TestBlock->GetTrueTarget()) !=
           loop->ContainsBlock(iterInfo.TestBlock->GetFalseTarget()));
    if (!iterInfo.TestBlock->TrueTargetIs(loop->GetHeader()) && !iterInfo.TestBlock->FalseTargetIs(loop->GetHeader()))
    {
        JITDUMP("Failed to unroll loop " FMT_LP ": test block is not a backedge\n", loop->GetIndex());
        return false;
    }

    // Get the loop data:
    //  - initial constant
    //  - limit constant
    //  - iterator
    //  - iterator increment
    //  - increment operation type (i.e. ADD, SUB, etc...)
    //  - loop test type (i.e. GT_GE, GT_LT, etc...)

    int        lbeg         = iterInfo.ConstInitValue;
    int        llim         = iterInfo.ConstLimit();
    genTreeOps testOper     = iterInfo.TestOper();
    unsigned   lvar         = iterInfo.IterVar;
    int        iterInc      = iterInfo.IterConst();
    genTreeOps iterOper     = iterInfo.IterOper();
    var_types  iterOperType = iterInfo.IterOperType();
    bool       unsTest      = (iterInfo.TestTree->gtFlags & GTF_UNSIGNED) != 0;

    assert(!lvaGetDesc(lvar)->IsAddressExposed());
    assert(!lvaGetDesc(lvar)->lvIsStructField);

    JITDUMP("Analyzing candidate for loop unrolling:\n");
    DBEXEC(verbose, FlowGraphNaturalLoop::Dump(loop));

    // Find the number of iterations - the function returns false if not a constant number.
    unsigned totalIter;
    if (!optComputeLoopRep(lbeg, llim, iterInc, iterOper, iterOperType, testOper, unsTest, &totalIter))
    {
        JITDUMP("Failed to unroll loop " FMT_LP ": not a constant iteration count\n", loop->GetIndex());
        return false;
    }

    JITDUMP("Computed loop repetition count (number of test block executions) to be %u\n", totalIter);

    // Forget it if there are too many repetitions or not a constant loop.

    if (totalIter > iterLimit)
    {
        JITDUMP("Failed to unroll loop " FMT_LP ": too many iterations (%d > %d) (heuristic)\n", loop->GetIndex(),
                totalIter, iterLimit);
        return false;
    }

    int unrollLimitSz = UNROLL_LIMIT_SZ[compCodeOpt()];

    if (INDEBUG(compStressCompile(STRESS_UNROLL_LOOPS, 50) ||) false)
    {
        // In stress mode, quadruple the size limit, and drop
        // the restriction that loop limit must be vector element count.
        unrollLimitSz *= 4;
    }
    else if (totalIter <= 1)
    {
        // No limit for single iteration loops
        // If there is no iteration (totalIter == 0), we will remove the loop body entirely.
        unrollLimitSz = INT_MAX;
    }
    else if (totalIter <= opts.compJitUnrollLoopMaxIterationCount)
    {
        // We can unroll this
    }
    else if (iterInfo.HasSimdLimit)
    {
        // We can unroll this
    }
    else
    {
        JITDUMP("Failed to unroll loop " FMT_LP ": insufficiently simple loop (heuristic)\n", loop->GetIndex());
        return false;
    }

    GenTree* incr = iterInfo.IterTree;

    // Don't unroll loops we don't understand.
    if (!incr->OperIs(GT_STORE_LCL_VAR))
    {
        JITDUMP("Failed to unroll loop " FMT_LP ": unknown increment op (%s)\n", loop->GetIndex(),
                GenTree::OpName(incr->gtOper));
        return false;
    }
    incr = incr->AsLclVar()->Data();

    // Make sure everything looks ok.
    assert((iterInfo.TestBlock != nullptr) && iterInfo.TestBlock->KindIs(BBJ_COND));

    // clang-format off
    if (!incr->OperIs(GT_ADD, GT_SUB) ||
        !incr->AsOp()->gtOp1->OperIs(GT_LCL_VAR) ||
        (incr->AsOp()->gtOp1->AsLclVarCommon()->GetLclNum() != lvar) ||
        !incr->AsOp()->gtOp2->OperIs(GT_CNS_INT) ||
        (incr->AsOp()->gtOp2->AsIntCon()->gtIconVal != iterInc) ||

        (iterInfo.TestBlock->lastStmt()->GetRootNode()->gtGetOp1() != iterInfo.TestTree))
    {
        noway_assert(!"Bad precondition in Compiler::optUnrollLoops()");
        return false;
    }
    // clang-format on

    bool unrollLoopsWithEH = false;
    INDEBUG(unrollLoopsWithEH = (JitConfig.JitUnrollLoopsWithEH() > 0);)
    INDEBUG(const char* reason);

    if (unrollLoopsWithEH)
    {
        if (!loop->CanDuplicateWithEH(INDEBUG(&reason)))
        {
            JITDUMP("Failed to unroll loop " FMT_LP ": %s\n", loop->GetIndex(), reason);
            return false;
        }
    }
    else if (!loop->CanDuplicate(INDEBUG(&reason)))
    {
        JITDUMP("Failed to unroll loop " FMT_LP ": %s\n", loop->GetIndex(), reason);
        return false;
    }

    // After this point, assume we've changed the IR. In particular, we call
    // gtSetStmtInfo() which can modify the IR.
    *changedIR = true;

    // Heuristic: Estimated cost in code size of the unrolled loop.
    // TODO: duplication cost is higher if there is EH...

    ClrSafeInt<unsigned> loopCostSz; // Cost is size of one iteration

    loop->VisitLoopBlocksReversePostOrder([=, &loopCostSz](BasicBlock* block) {
        for (Statement* const stmt : block->Statements())
        {
            gtSetStmtInfo(stmt);
            loopCostSz += stmt->GetCostSz();
        }

        return BasicBlockVisit::Continue;
    });

#ifdef DEBUG
    // Today we will never see any BBJ_RETURN blocks because we cannot
    // duplicate loops with EH in them. When we have no try-regions that start
    // in the loop it is not possible for BBJ_RETURN blocks to be part of the
    // loop; a BBJ_RETURN block can only be part of the loop if its exceptional
    // flow can reach the header, but that would require the handler to also be
    // part of the loop, which guarantees that the loop contains two distinct
    // EH regions.
    loop->VisitLoopBlocks([](BasicBlock* block) {
        assert(!block->KindIs(BBJ_RETURN));
        return BasicBlockVisit::Continue;
    });
#endif

    // Compute the estimated increase in code size for the unrolled loop.

    ClrSafeInt<unsigned> fixedLoopCostSz(8);

    ClrSafeInt<int> unrollCostSz =
        ClrSafeInt<int>(loopCostSz * ClrSafeInt<unsigned>(totalIter)) - ClrSafeInt<int>(loopCostSz + fixedLoopCostSz);

    // Don't unroll if too much code duplication would result.

    if (unrollCostSz.IsOverflow() || (unrollCostSz.Value() > unrollLimitSz))
    {
        JITDUMP("Failed to unroll loop " FMT_LP ": size constraint (%d > %d) (heuristic)\n", loop->GetIndex(),
                unrollCostSz.Value(), unrollLimitSz);
        return false;
    }

    // Looks like a good idea to unroll this loop, let's do it!
    JITDUMP("\nUnrolling loop " FMT_LP " unrollCostSz = %d\n", loop->GetIndex(), unrollCostSz.Value());
    JITDUMPEXEC(FlowGraphNaturalLoop::Dump(loop));

    // We unroll a loop focused around the test and IV that was
    // identified by FlowGraphNaturalLoop::AnalyzeIteration. Note that:
    //
    // * The loop can have multiple exits. The exit guarded on the IV
    //   is the one we can optimize away when we unroll, since we know
    //   the value of the IV in each iteration. The other exits will
    //   remain in place in each iteration.
    //
    // * The loop can have multiple backedges. Often, there is a
    //   single backedge that becomes statically unreachable when we
    //   optimize the exit guarded on the IV. In that case the loop
    //   structure disappears. However, if there were multiple backedges,
    //   the loop structure can remain in each unrolled iteration.
    //
    // * The loop being unrolled can also have nested loops, which will
    //   be duplicated for each unrolled iteration.
    //
    // * Unrolling a loop creates or removes basic blocks, depending on
    //   whether the iter count is 0. When nested loops are unrolled,
    //   instead of trying to maintain the new right set of loop blocks
    //   that exist in all ancestor loops, we skip unrolling for all
    //   ancestor loops and instead recompute the loop structure and
    //   retry unrolling. It is rare to have multiple nested unrollings
    //   of loops, so this is not a TP issue.

    BlockToBlockMap blockMap(getAllocator(CMK_LoopUnroll));

    BasicBlock* bottom        = loop->GetLexicallyBottomMostBlock();
    BasicBlock* insertAfter   = bottom;
    BasicBlock* prevTestBlock = nullptr;
    unsigned    iterToUnroll  = totalIter; // The number of iterations left to unroll

    // Find the exit block of the IV test first. We need to do that
    // here since it may have implicit fallthrough that we'll change
    // below.
    BasicBlock* exiting = iterInfo.TestBlock;
    assert(exiting->KindIs(BBJ_COND));
    assert(loop->ContainsBlock(exiting->GetTrueTarget()) != loop->ContainsBlock(exiting->GetFalseTarget()));
    BasicBlock* exit =
        loop->ContainsBlock(exiting->GetTrueTarget()) ? exiting->GetFalseTarget() : exiting->GetTrueTarget();

    for (int lval = lbeg; iterToUnroll > 0; iterToUnroll--)
    {
        // Block weight should no longer have the loop multiplier
        //
        // Note this is not quite right, as we may not have upscaled by this amount
        // and we might not have upscaled at all, if we had profile data.
        //
        weight_t scaleWeight = 1.0 / BB_LOOP_WEIGHT_SCALE;

        if (unrollLoopsWithEH)
        {
            loop->DuplicateWithEH(&insertAfter, &blockMap, scaleWeight);
        }
        else
        {
            loop->Duplicate(&insertAfter, &blockMap, scaleWeight);
        }

        // Replace all uses of the loop iterator with the current value.
        loop->VisitLoopBlocks([=, &blockMap](BasicBlock* block) {
            optReplaceScalarUsesWithConst(blockMap[block], lvar, lval);
            return BasicBlockVisit::Continue;
        });

        // Remove the test we created in the duplicate; we're doing a full unroll.
        BasicBlock* testBlock = blockMap[iterInfo.TestBlock];

        optRedirectPrevUnrollIteration(loop, prevTestBlock, blockMap[loop->GetHeader()]);

        // Save the test block of the previously unrolled
        // iteration, so that we can redirect it when we create
        // the next iteration (or to the exit for the last
        // iteration).
        prevTestBlock = testBlock;

        // update the new value for the unrolled iterator

        switch (iterOper)
        {
            case GT_ADD:
                lval += iterInc;
                break;

            case GT_SUB:
                lval -= iterInc;
                break;

            default:
                unreached();
        }
    }

    // If we get here, we successfully cloned all the blocks in the
    // unrolled loop. Note we may not have done any cloning at all if
    // the loop iteration count was computed to be zero. Such loops are
    // guaranteed to be unreachable since if the repetition count is
    // zero the loop invariant is false on the first iteration, yet
    // FlowGraphNaturalLoop::AnalyzeIteration only returns true if the
    // loop invariant is true on every iteration. That means we have a
    // guarding check before we enter the loop that will always be
    // false.
    optRedirectPrevUnrollIteration(loop, prevTestBlock, exit);

    // The old loop body is unreachable now, but we will remove those
    // blocks after we finish unrolling.

#ifdef DEBUG
    if (verbose)
    {
        printf("Whole unrolled loop:\n");

        gtDispTree(iterInfo.InitTree);
        printf("\n");
        fgDumpTrees(bottom->Next(), insertAfter);
    }
#endif // DEBUG

    return true;
}

//-----------------------------------------------------------------------------
// optRedirectPrevUnrollIteration:
//   Redirect the previous unrolled loop iteration (or entry) to a new target.
//
// Parameters:
//   loop          - The loop that is being unrolled
//   prevTestBlock - The test block of the previous iteration, or nullptr if
//                   this is the first unrolled iteration.
//   target        - The new target for the previous iteration.
//
//
// Remarks:
//   If "prevTestBlock" is nullptr, then the entry edges of the loop are
//   redirected to the target. Otherwise "prevTestBlock" has its terminating
//   statement removed and is changed to a BBJ_ALWAYS that goes to the target.
//
void Compiler::optRedirectPrevUnrollIteration(FlowGraphNaturalLoop* loop, BasicBlock* prevTestBlock, BasicBlock* target)
{
    if (prevTestBlock != nullptr)
    {
        assert(prevTestBlock->KindIs(BBJ_COND));
        Statement* testCopyStmt = prevTestBlock->lastStmt();
        GenTree*   testCopyExpr = testCopyStmt->GetRootNode();
        assert(testCopyExpr->OperIs(GT_JTRUE));
        GenTree* sideEffList = nullptr;
        gtExtractSideEffList(testCopyExpr, &sideEffList, GTF_SIDE_EFFECT | GTF_ORDER_SIDEEFF);
        if (sideEffList == nullptr)
        {
            fgRemoveStmt(prevTestBlock, testCopyStmt);
        }
        else
        {
            testCopyStmt->SetRootNode(sideEffList);
        }

        // Redirect exit edge from previous iteration to new entry.
        fgRedirectEdge(prevTestBlock->TrueEdgeRef(), target);
        fgRemoveRefPred(prevTestBlock->GetFalseEdge());
        prevTestBlock->SetKindAndTargetEdge(BBJ_ALWAYS, prevTestBlock->GetTrueEdge());

        JITDUMP("Redirecting previously created exiting " FMT_BB " -> " FMT_BB "\n", prevTestBlock->bbNum,
                target->bbNum);
    }
    else
    {
        // Redirect all predecessors to the new one.
        for (FlowEdge* enterEdge : loop->EntryEdges())
        {
            BasicBlock* entering = enterEdge->getSourceBlock();
            JITDUMP("Redirecting " FMT_BB " -> " FMT_BB " to " FMT_BB " -> " FMT_BB "\n", entering->bbNum,
                    loop->GetHeader()->bbNum, entering->bbNum, target->bbNum);
            assert(!entering->KindIs(BBJ_COND)); // Ensured by canonicalization
            fgReplaceJumpTarget(entering, loop->GetHeader(), target);
        }
    }
}

//-----------------------------------------------------------------------------
// optReplaceScalarUsesWithConst: Replace all GT_LCL_VAR occurrences of a local
// with a constant.
//
// Arguments:
//   block   - The block to replace in
//   lclNum  - The local to replace
//   cnsVal  - The constant to replace with
//
// Remarks:
//   This is used to replace the loop iterator with the constant value when
//   unrolling.
//
void Compiler::optReplaceScalarUsesWithConst(BasicBlock* block, unsigned lclNum, ssize_t cnsVal)
{
    class ReplaceVisitor final : public GenTreeVisitor<ReplaceVisitor>
    {
        unsigned m_lclNum;
        ssize_t  m_cnsVal;

    public:
        enum
        {
            DoPreOrder    = true,
            DoLclVarsOnly = true,
        };

        bool MadeChanges = false;

        ReplaceVisitor(Compiler* comp, unsigned lclNum, ssize_t cnsVal)
            : GenTreeVisitor(comp)
            , m_lclNum(lclNum)
            , m_cnsVal(cnsVal)
        {
        }

        fgWalkResult PreOrderVisit(GenTree** use, GenTree* user)
        {
            if ((*use)->OperIs(GT_LCL_VAR) && ((*use)->AsLclVarCommon()->GetLclNum() == m_lclNum))
            {
                *use        = m_compiler->gtNewIconNode(m_cnsVal, genActualType(*use));
                MadeChanges = true;
            }

            return fgWalkResult::WALK_CONTINUE;
        }
    };

    ReplaceVisitor visitor(this, lclNum, cnsVal);

    for (Statement* stmt : block->Statements())
    {
        visitor.WalkTree(stmt->GetRootNodePointer(), nullptr);

        if (visitor.MadeChanges)
        {
            // Replacing locals with constants can change whether we consider
            // something to have side effects. For example, `fgAddrCouldBeNull`
            // can switch from true to false if the address changes from
            // ADD(LCL_ADDR, LCL_VAR) -> ADD(LCL_ADDR, CNS_INT).
            gtUpdateStmtSideEffects(stmt);
            visitor.MadeChanges = false;
        }
    }
}

Compiler::OptInvertCountTreeInfoType Compiler::optInvertCountTreeInfo(GenTree* tree)
{
    class CountTreeInfoVisitor : public GenTreeVisitor<CountTreeInfoVisitor>
    {
    public:
        enum
        {
            DoPreOrder = true,
        };

        Compiler::OptInvertCountTreeInfoType Result = {};

        CountTreeInfoVisitor(Compiler* comp)
            : GenTreeVisitor(comp)
        {
        }

        fgWalkResult PreOrderVisit(GenTree** use, GenTree* user)
        {
            if (Compiler::IsSharedStaticHelper(*use))
            {
                Result.sharedStaticHelperCount++;
            }

            if ((*use)->OperIsArrLength())
            {
                Result.arrayLengthCount++;
            }

            return fgWalkResult::WALK_CONTINUE;
        }
    };

    CountTreeInfoVisitor walker(this);
    walker.WalkTree(&tree, nullptr);
    return walker.Result;
}

//-----------------------------------------------------------------------------
// optTryInvertWhileLoop: modify flow and duplicate code so that for/while loops are
//   entered at top and tested at bottom (aka loop rotation or bottom testing).
//   Creates a "zero trip test" condition which guards entry to the loop.
//   Enables loop invariant hoisting and loop cloning, which depend on
//   `do {} while` format loops.
//
// Arguments:
//   block -- block that may be the predecessor of the un-rotated loop's test block.
//
// Returns:
//   true if any IR changes possibly made (used to determine phase return status)
//
bool Compiler::optTryInvertWhileLoop(FlowGraphNaturalLoop* loop)
{
    // Should have preheaders at this point
    assert(loop->EntryEdges().size() == 1);
    BasicBlock* const preheader = loop->EntryEdge(0)->getSourceBlock();

    ArrayStack<BasicBlock*> duplicatedBlocks(getAllocator(CMK_LoopOpt));

    BasicBlock* condBlock = loop->GetHeader();
    while (true)
    {
        if (!BasicBlock::sameEHRegion(preheader, condBlock))
        {
            JITDUMP("No loop-inversion for " FMT_LP
                    " since we could not find a condition block in the same EH region as the preheader\n",
                    loop->GetIndex());
            return false;
        }

        duplicatedBlocks.Push(condBlock);

        if (condBlock->KindIs(BBJ_ALWAYS))
        {
            condBlock = condBlock->GetTarget();

            if (!loop->ContainsBlock(condBlock) || (condBlock == loop->GetHeader()))
            {
                JITDUMP("No loop-inversion for " FMT_LP "; ran out of blocks following BBJ_ALWAYS blocks\n",
                        loop->GetIndex());
                return false;
            }

            continue;
        }

        if (!condBlock->KindIs(BBJ_COND))
        {
            JITDUMP("No loop-inversion for " FMT_LP " since we could not find any BBJ_COND block\n", loop->GetIndex());
            return false;
        }

        break;
    }

    const bool trueExits  = !loop->ContainsBlock(condBlock->GetTrueTarget());
    const bool falseExits = !loop->ContainsBlock(condBlock->GetFalseTarget());

    if (trueExits == falseExits)
    {
        JITDUMP("No loop-inversion for " FMT_LP " since we could not find any exiting BBJ_COND block\n",
                loop->GetIndex());
        return false;
    }

    BasicBlock* const exit           = trueExits ? condBlock->GetTrueTarget() : condBlock->GetFalseTarget();
    BasicBlock* const stayInLoopSucc = trueExits ? condBlock->GetFalseTarget() : condBlock->GetTrueTarget();

    // If the condition is already a latch, then the loop is already inverted
    if (stayInLoopSucc == loop->GetHeader())
    {
        JITDUMP("No loop-inversion for " FMT_LP " since it is already inverted\n", loop->GetIndex());
        return false;
    }

    // Exiting the loop may enter a new try-region. However, to keep exits canonical, we will
    // have to split the exit such that old loop edges exit to one half, while the duplicated condition
    // exits to the other half. This will result in jump into the middle of a try-region, which is illegal.
    // TODO: We can fix this by placing the first half of the split (which will be an empty block) outside
    // the try region.
    if (!BasicBlock::sameEHRegion(preheader, exit))
    {
        JITDUMP("No loop-inversion for " FMT_LP " since the preheader " FMT_BB " and exit " FMT_BB
                " are in different EH regions\n",
                loop->GetIndex(), preheader->bbNum, exit->bbNum);
        return false;
    }

    JITDUMP("Condition in block " FMT_BB " of loop " FMT_LP " is a candidate for duplication to invert the loop\n",
            condBlock->bbNum, loop->GetIndex());

    // Check if loop is small enough to consider for inversion.
    // Large loops are less likely to benefit from inversion.
    const int invertSizeLimit = JitConfig.JitLoopInversionSizeLimit();
    if (invertSizeLimit >= 0)
    {
        const int cloneSizeLimit          = JitConfig.JitCloneLoopsSizeLimit();
        bool      mightBenefitFromCloning = false;
        unsigned  loopSize                = 0;

        // Loops with bounds checks can benefit from cloning, which depends on inversion running.
        // Thus, we will try to proceed with inversion for slightly oversize loops if they show potential for cloning.
        auto countNode = [&mightBenefitFromCloning, &loopSize](GenTree* tree) -> unsigned {
            mightBenefitFromCloning |= tree->OperIs(GT_BOUNDS_CHECK);
            loopSize++;
            return 1;
        };

        optLoopComplexityExceeds(loop, (unsigned)max(invertSizeLimit, cloneSizeLimit), countNode);
        if (loopSize > (unsigned)invertSizeLimit)
        {
            // Don't try to invert oversize loops if they don't show cloning potential,
            // or if they're too big to be cloned anyway.
            JITDUMP(FMT_LP " exceeds inversion size limit of %d\n", loop->GetIndex(), invertSizeLimit);
            const bool tooBigToClone = (cloneSizeLimit >= 0) && (loopSize > (unsigned)cloneSizeLimit);
            if (!mightBenefitFromCloning || tooBigToClone)
            {
                JITDUMP("No inversion for " FMT_LP ": %s\n", loop->GetIndex(),
                        tooBigToClone ? "too big to clone" : "unlikely to benefit from cloning");
                return false;
            }

            // If the loop shows cloning potential, tolerate some excess size.
            const unsigned liberalInvertSizeLimit = (unsigned)(invertSizeLimit * 1.25);
            if (loopSize > liberalInvertSizeLimit)
            {
                JITDUMP(FMT_LP " might benefit from cloning, but is too large to invert.\n", loop->GetIndex());
                return false;
            }

            JITDUMP(FMT_LP " might benefit from cloning. Continuing.\n", loop->GetIndex());
        }
    }

    unsigned estDupCostSz = 0;

    for (int i = 0; i < duplicatedBlocks.Height(); i++)
    {
        BasicBlock* block = duplicatedBlocks.Bottom(i);
        for (Statement* stmt : block->Statements())
        {
            GenTree* tree = stmt->GetRootNode();
            gtPrepareCost(tree);
            estDupCostSz += tree->GetCostSz();
        }
    }

    weight_t       loopIterations       = BB_LOOP_WEIGHT_SCALE;
    bool           haveProfileWeights   = false;
    weight_t const weightPreheader      = preheader->bbWeight;
    weight_t const weightCond           = condBlock->bbWeight;
    weight_t const weightStayInLoopSucc = stayInLoopSucc->bbWeight;

    // If we have profile data then we calculate the number of times
    // the loop will iterate into loopIterations
    if (fgIsUsingProfileWeights())
    {
        // Only rely upon the profile weight when all three of these blocks
        // have good profile weights
        if (preheader->hasProfileWeight() && condBlock->hasProfileWeight() && stayInLoopSucc->hasProfileWeight())
        {
            // If this while loop never iterates then don't bother transforming
            //
            if (weightStayInLoopSucc == BB_ZERO_WEIGHT)
            {
                JITDUMP("No loop-inversion for " FMT_LP " since the in-loop successor " FMT_BB " has 0 weight\n",
                        loop->GetIndex(), preheader->bbNum);
                return false;
            }

            haveProfileWeights = true;

            // We generally expect weightCond > weightStayInLoopSucc
            //
            // Tolerate small inconsistencies...
            //
            if (!fgProfileWeightsConsistent(weightPreheader + weightStayInLoopSucc, weightCond))
            {
                JITDUMP("Profile weights locally inconsistent: preheader " FMT_WT ", stayInLoopSucc " FMT_WT
                        ", cond " FMT_WT "\n",
                        weightPreheader, weightStayInLoopSucc, weightCond);
            }
            else
            {
                // Determine average iteration count
                //
                //   weightTop is the number of time this loop executes
                //   weightTest is the number of times that we consider entering or remaining in the loop
                //   loopIterations is the average number of times that this loop iterates
                //
                weight_t loopEntries = weightCond - weightStayInLoopSucc;

                // If profile is inaccurate, try and use other data to provide a credible estimate.
                // The value should at least be >= weightBlock.
                //
                if (loopEntries < weightPreheader)
                {
                    loopEntries = weightPreheader;
                }

                loopIterations = weightStayInLoopSucc / loopEntries;
            }
        }
        else
        {
            JITDUMP("Missing profile data for loop!\n");
        }
    }

    unsigned maxDupCostSz = 34;

    if ((compCodeOpt() == FAST_CODE) || compStressCompile(STRESS_DO_WHILE_LOOPS, 30))
    {
        maxDupCostSz *= 4;
    }

    // If this loop iterates a lot then raise the maxDupCost
    if (loopIterations >= 12.0)
    {
        maxDupCostSz *= 2;
        if (loopIterations >= 96.0)
        {
            maxDupCostSz *= 2;
        }
    }

    bool costIsTooHigh = (estDupCostSz > maxDupCostSz);

    OptInvertCountTreeInfoType optInvertTotalInfo = {};
    if (costIsTooHigh)
    {
        // If we already know that the cost is acceptable, then don't waste time walking the tree
        // counting things to boost the maximum allowed cost.
        //
        // If the loop condition has a shared static helper, we really want this loop converted
        // as not converting the loop will disable loop hoisting, meaning the shared helper will
        // be executed on every loop iteration.
        //
        // If the condition has array.Length operations, also boost, as they are likely to be CSE'd.

        for (int i = 0; i < duplicatedBlocks.Height() && costIsTooHigh; i++)
        {
            BasicBlock* block = duplicatedBlocks.Bottom(i);
            for (Statement* const stmt : block->Statements())
            {
                GenTree* tree = stmt->GetRootNode();

                OptInvertCountTreeInfoType optInvertInfo = optInvertCountTreeInfo(tree);
                optInvertTotalInfo.sharedStaticHelperCount += optInvertInfo.sharedStaticHelperCount;
                optInvertTotalInfo.arrayLengthCount += optInvertInfo.arrayLengthCount;

                if ((optInvertInfo.sharedStaticHelperCount > 0) || (optInvertInfo.arrayLengthCount > 0))
                {
                    // Calculate a new maximum cost. We might be able to early exit.

                    unsigned newMaxDupCostSz =
                        maxDupCostSz +
                        24 * min(optInvertTotalInfo.sharedStaticHelperCount, (int)(loopIterations + 1.5)) +
                        8 * optInvertTotalInfo.arrayLengthCount;

                    // Is the cost too high now?
                    costIsTooHigh = (estDupCostSz > newMaxDupCostSz);
                    if (!costIsTooHigh)
                    {
                        // No need counting any more trees; we're going to do the transformation.
                        JITDUMP("Decided to duplicate loop condition block after counting helpers in tree [%06u] in "
                                "block " FMT_BB,
                                dspTreeID(tree), block->bbNum);
                        maxDupCostSz = newMaxDupCostSz; // for the JitDump output below
                        break;
                    }
                }
            }
        }
    }

#ifdef DEBUG
    if (verbose)
    {
        // Note that `optInvertTotalInfo.sharedStaticHelperCount = 0` means either there were zero helpers, or the
        // tree walk to count them was not done.
        printf(
            "\nDuplication of loop condition [%06u] is %s, because the cost of duplication (%i) is %s than %i,"
            "\n   loopIterations = %7.3f, optInvertTotalInfo.sharedStaticHelperCount >= %d, haveProfileWeights = %s\n",
            dspTreeID(condBlock->lastStmt()->GetRootNode()), costIsTooHigh ? "not done" : "performed", estDupCostSz,
            costIsTooHigh ? "greater" : "less or equal", maxDupCostSz, loopIterations,
            optInvertTotalInfo.sharedStaticHelperCount, dspBool(haveProfileWeights));
    }
#endif

    if (costIsTooHigh)
    {
        return true;
    }

    // Split the preheader so we can duplicate the statements into it. The new
    // block will be the new preheader.
    BasicBlock* const newPreheader = fgSplitBlockAtEnd(preheader);

    // Make sure exit stays canonical
    BasicBlock* nonEnterBlock = fgSplitBlockAtBeginning(exit);

    JITDUMP("New preheader is " FMT_BB "\n", newPreheader->bbNum);
    JITDUMP("Duplicated condition block is " FMT_BB "\n", preheader->bbNum);
    JITDUMP("Old exit is " FMT_BB ", new non-enter block is " FMT_BB "\n", exit->bbNum, nonEnterBlock->bbNum);

    // Get the newCond -> newPreheader edge
    FlowEdge* const newCondToNewPreheader = preheader->GetTargetEdge();

    // Add newCond -> nonEnterBlock
    FlowEdge* const newCondToNewExit = fgAddRefPred(nonEnterBlock, preheader);

    preheader->SetCond(trueExits ? newCondToNewExit : newCondToNewPreheader,
                       trueExits ? newCondToNewPreheader : newCondToNewExit);

    preheader->GetTrueEdge()->setLikelihood(condBlock->GetTrueEdge()->getLikelihood());
    preheader->GetFalseEdge()->setLikelihood(condBlock->GetFalseEdge()->getLikelihood());

    // Redirect newPreheader from header to stayInLoopSucc
    fgRedirectEdge(newPreheader->TargetEdgeRef(), stayInLoopSucc);

    // Duplicate all the code now
    for (int i = 0; i < duplicatedBlocks.Height(); i++)
    {
        BasicBlock* block = duplicatedBlocks.Bottom(i);
        for (Statement* stmt : block->Statements())
        {
            GenTree*   clonedTree = gtCloneExpr(stmt->GetRootNode());
            Statement* clonedStmt = fgNewStmtAtEnd(preheader, clonedTree, stmt->GetDebugInfo());

            if (stmt == condBlock->lastStmt())
            {
                // TODO: This ought not to be necessary, but has large negative diffs if we don't do it
                assert(clonedStmt->GetRootNode()->OperIs(GT_JTRUE));
                clonedStmt->GetRootNode()->AsUnOp()->gtOp1 = gtReverseCond(clonedStmt->GetRootNode()->gtGetOp1());
                preheader->SetCond(preheader->GetFalseEdge(), preheader->GetTrueEdge());
            }

            DISPSTMT(clonedStmt);
        }

        preheader->CopyFlags(block, BBF_COPY_PROPAGATE);
    }

    if (haveProfileWeights)
    {
        // Reduce flow into the new loop entry/exit blocks
        newPreheader->setBBProfileWeight(newCondToNewPreheader->getLikelyWeight());
        exit->decreaseBBProfileWeight(newCondToNewExit->getLikelyWeight());

        // Update the duplicated blocks' weights

        for (int i = 0; i < (duplicatedBlocks.Height() - 1); i++)
        {
            BasicBlock* block = duplicatedBlocks.Bottom(i);
            block->setBBProfileWeight(block->computeIncomingWeight());
        }

        condBlock->setBBProfileWeight(condBlock->computeIncomingWeight());
    }

    // Finally compact the condition with its pred if that is possible now.
    // TODO-Cleanup: This compensates for limitations in analysis of downstream
    // phases, particularly the pattern-based IV analysis.
    BasicBlock* const condPred = condBlock->GetUniquePred(this);
    if (condPred != nullptr)
    {
        JITDUMP("Cond block " FMT_BB " has a unique pred now, seeing if we can compact...\n", condBlock->bbNum);
        if (fgCanCompactBlock(condPred))
        {
            JITDUMP("  ..we can!\n");
            fgCompactBlock(condPred);
            condBlock = condPred;
        }
        else
        {
            JITDUMP("  ..we cannot\n");
        }
    }

#ifdef DEBUG
    if (verbose)
    {
        printf("\nDuplicated loop exit block at " FMT_BB " for loop " FMT_LP "\n", preheader->bbNum, loop->GetIndex());
        printf("Estimated code size expansion is %d\n", estDupCostSz);

        fgDumpBlock(preheader);
        fgDumpBlock(condBlock);
    }
#endif // DEBUG

    Metrics.LoopsInverted++;
    return true;
}

//-----------------------------------------------------------------------------
// optInvertLoops: invert while loops in the method
//
// Returns:
//   suitable phase status
//
PhaseStatus Compiler::optInvertLoops()
{
#if defined(OPT_CONFIG)
    if (!JitConfig.JitDoLoopInversion())
    {
        JITDUMP("Loop inversion disabled\n");
        return PhaseStatus::MODIFIED_NOTHING;
    }
#endif // OPT_CONFIG

    if (compCodeOpt() == SMALL_CODE)
    {
        return PhaseStatus::MODIFIED_NOTHING;
    }

    bool madeChanges = false;
    for (FlowGraphNaturalLoop* loop : m_loops->InPostOrder())
    {
        madeChanges |= optTryInvertWhileLoop(loop);
    }

    if (Metrics.LoopsInverted > 0)
    {
        assert(madeChanges);
        fgInvalidateDfsTree();
        m_dfsTree = fgComputeDfs();
        m_loops   = FlowGraphNaturalLoops::Find(m_dfsTree);

        // In normal cases no further canonicalization will be required as we
        // try to ensure loops stay canonicalized during inversion. However,
        // duplicating the condition outside an inner loop can introduce new
        // exits in the parent loop, so we may rarely need to recanonicalize
        // exit blocks.
        if (optCanonicalizeLoops())
        {
            fgInvalidateDfsTree();
            m_dfsTree = fgComputeDfs();
            m_loops   = FlowGraphNaturalLoops::Find(m_dfsTree);
        }
    }

    return madeChanges ? PhaseStatus::MODIFIED_EVERYTHING : PhaseStatus::MODIFIED_NOTHING;
}

//-----------------------------------------------------------------------------
// optOptimizeFlow: Simplify flowgraph, and run a few flow optimizations
//
// Returns:
//   suitable phase status
//
PhaseStatus Compiler::optOptimizeFlow()
{
    noway_assert(opts.OptimizationEnabled());

    bool modified = fgUpdateFlowGraph(/* doTailDuplication */ true);

    // TODO: Always rely on profile synthesis to identify cold blocks.
    if (!fgIsUsingProfileWeights())
    {
        modified |= fgExpandRarelyRunBlocks();
    }

    return modified ? PhaseStatus::MODIFIED_EVERYTHING : PhaseStatus::MODIFIED_NOTHING;
}

//-----------------------------------------------------------------------------
// optOptimizePreLayout: Optimizes flow before reordering blocks.
//
// Returns:
//   suitable phase status
//
PhaseStatus Compiler::optOptimizePreLayout()
{
    assert(opts.OptimizationEnabled());

    bool modified = fgUpdateFlowGraph();

    // TODO: Always rely on profile synthesis to identify cold blocks.
    if (!fgIsUsingProfileWeights())
    {
        modified |= fgExpandRarelyRunBlocks();
    }

    // Run a late pass of unconditional-to-conditional branch optimization, skipping handler blocks.
    for (BasicBlock* block = fgFirstBB; block != fgFirstFuncletBB; block = block->Next())
    {
        if (!UsesFunclets() && block->hasHndIndex())
        {
            block = ehGetDsc(block->getHndIndex())->ebdHndLast;
            continue;
        }

        modified |= fgOptimizeBranch(block);
    }

    return modified ? PhaseStatus::MODIFIED_EVERYTHING : PhaseStatus::MODIFIED_NOTHING;
}

//-----------------------------------------------------------------------------
// optOptimizePostLayout: Optimize flow after block layout is finalized
//
// Returns:
//   suitable phase status
//
PhaseStatus Compiler::optOptimizePostLayout()
{
    assert(opts.OptimizationEnabled());
    PhaseStatus status = PhaseStatus::MODIFIED_NOTHING;

    for (BasicBlock* const block : Blocks())
    {
        // Reverse conditions to enable fallthrough flow into BBJ_COND's false target
        if (block->KindIs(BBJ_COND) && block->CanRemoveJumpToTarget(block->GetTrueTarget(), this))
        {
            GenTree* const test = block->lastNode();
            assert(test->OperIsConditionalJump());

            if (test->OperIs(GT_JTRUE))
            {
                // Flip GT_JTRUE node's conditional operand, and handle any new nodes this may introduce
                GenTree* const cond    = test->gtGetOp1();
                GenTree* const newCond = gtReverseCond(cond);
                if (cond != newCond)
                {
                    LIR::AsRange(block).InsertAfter(cond, newCond);
                    test->AsUnOp()->gtOp1 = newCond;
                }
            }
            else
            {
                // gtReverseCond can handle other conditional jumps without introducing a new node
                GenTree* const cond = gtReverseCond(test);
                assert(cond == test);
            }

            FlowEdge* const oldTrueEdge  = block->GetTrueEdge();
            FlowEdge* const oldFalseEdge = block->GetFalseEdge();
            block->SetTrueEdge(oldFalseEdge);
            block->SetFalseEdge(oldTrueEdge);

            assert(block->CanRemoveJumpToTarget(block->GetFalseTarget(), this));
            status = PhaseStatus::MODIFIED_EVERYTHING;
        }
    }

    return status;
}

//-----------------------------------------------------------------------------
// optResetLoopInfo: reset all loop info in preparation for refinding the loops
// and scaling blocks based on it.
//
void Compiler::optResetLoopInfo()
{
#ifdef DEBUG
    if (verbose)
    {
        printf("*************** In optResetLoopInfo()\n");
    }
#endif

    for (BasicBlock* const block : Blocks())
    {
        // If the block weight didn't come from profile data, reset it so it can be calculated again.
        if (!block->hasProfileWeight())
        {
            block->bbWeight = BB_UNITY_WEIGHT;
        }
    }
}

//-----------------------------------------------------------------------------
// optFindLoopsPhase: find loops in the function.
//
// The JIT recognizes two types of loops in a function: natural loops and "general" (or "unnatural") loops.
// Natural loops are those which get added to Compiler::m_loops. Most downstream optimizations require
// using natural loops. See `FlowGraphNaturalLoop` for a definition of the criteria satisfied by a natural loop.
// A general loop is defined as a lexical (program order) range of blocks where a later block branches to an
// earlier block (that is, there is a back edge in the flow graph), and the later block is reachable from the earlier
// block. General loops are used for weighting flow graph blocks (when there is no block profile data).
//
// Notes:
//  Also (re)sets all non-IBC block weights.
//
PhaseStatus Compiler::optFindLoopsPhase()
{
#ifdef DEBUG
    if (verbose)
    {
        printf("*************** In optFindLoopsPhase()\n");
    }
#endif

    assert(m_dfsTree != nullptr);
    optFindLoops();

    Metrics.LoopsFoundDuringOpts = (int)m_loops->NumLoops();

    return PhaseStatus::MODIFIED_EVERYTHING;
}

//-----------------------------------------------------------------------------
// optFindLoops: Find, compact and canonicalize natural loops.
//
void Compiler::optFindLoops()
{
    m_loops = FlowGraphNaturalLoops::Find(m_dfsTree);

    optCompactLoops();

    if (optCanonicalizeLoops())
    {
        fgInvalidateDfsTree();
        m_dfsTree = fgComputeDfs();
        m_loops   = FlowGraphNaturalLoops::Find(m_dfsTree);
    }

    // Starting now we require all loops to be in canonical form.
    optLoopsCanonical = true;

    // Leave a bread crumb for future phases like loop alignment about whether
    // looking for loops makes sense. We generally do not expect phases to
    // introduce new cycles/loops in the flow graph; if they do, they should
    // set this to true themselves.
    // We use more general cycles over "m_loops->NumLoops() > 0" here because
    // future optimizations can easily cause general cycles to become natural
    // loops by removing edges.
    fgMightHaveNaturalLoops = m_dfsTree->HasCycle();
    assert(fgMightHaveNaturalLoops || (m_loops->NumLoops() == 0));
}

//-----------------------------------------------------------------------------
// optCanonicalizeLoops: Canonicalize natural loops.
//
// Parameters:
//   loops - Structure containing loops
//
// Returns:
//   True if any flow graph modifications were made
//
// Remarks:
//   Guarantees that all natural loops have preheaders.
//
bool Compiler::optCanonicalizeLoops()
{
    bool changed = false;

    for (FlowGraphNaturalLoop* loop : m_loops->InReversePostOrder())
    {
        changed |= optCreatePreheader(loop);
    }

    // At this point we've created preheaders. That means we are working with
    // stale loop and DFS data. However, we can do exit canonicalization even
    // on the stale data; this relies on the fact that exiting blocks do not
    // change as a result of creating preheaders. On the other hand the exit
    // blocks themselves may have changed (previously it may have been another
    // loop's header, now it might be its preheader instead). Exit
    // canonicalization still works even with this.
    //
    // The exit canonicalization needs to be done in post order (inner -> outer
    // loops) so that inner exits that also exit outer loops have proper exit
    // blocks created for each loop.
    for (FlowGraphNaturalLoop* loop : m_loops->InPostOrder())
    {
        changed |= optCanonicalizeExits(loop);
    }

    // We may have created preheaders in different EH regions than the loop
    // header. If so, split the header to put it into the same region as the preheader.
    for (FlowGraphNaturalLoop* loop : m_loops->InReversePostOrder())
    {
        changed |= optSplitHeaderIfNecessary(loop);
    }

    return changed;
}

//-----------------------------------------------------------------------------
// optCompactLoops: Compact loops to make their loop blocks lexical if possible.
//
void Compiler::optCompactLoops()
{
    for (FlowGraphNaturalLoop* loop : m_loops->InReversePostOrder())
    {
        optCompactLoop(loop);
    }
}

//-----------------------------------------------------------------------------
// optCompactLoop: Compact a specific loop.
//
// Parameters:
//   loop - The loop
//
void Compiler::optCompactLoop(FlowGraphNaturalLoop* loop)
{
    BasicBlock* insertionPoint = nullptr;

    BasicBlock* top           = loop->GetLexicallyTopMostBlock();
    unsigned    numLoopBlocks = loop->NumLoopBlocks();

    BasicBlock* cur = top;
    while (numLoopBlocks > 0)
    {
        if (loop->ContainsBlock(cur))
        {
            numLoopBlocks--;
            cur = cur->Next();
            continue;
        }

        // If this is a CALLFINALLYRET that is not in the loop, but the
        // CALLFINALLY was, then we have to leave it in place. For compaction
        // purposes this doesn't really make any difference, since no codegen
        // is associated with the CALLFINALLYRET anyway.
        if (cur->isBBCallFinallyPairTail())
        {
            cur = cur->Next();
            continue;
        }

        BasicBlock* lastNonLoopBlock = cur;
        while (true)
        {
            // Should always have a "bottom" block of the loop where we stop.
            assert(lastNonLoopBlock->Next() != nullptr);
            if (loop->ContainsBlock(lastNonLoopBlock->Next()))
            {
                break;
            }

            lastNonLoopBlock = lastNonLoopBlock->Next();
        }

        if (insertionPoint == nullptr)
        {
            insertionPoint = loop->GetLexicallyBottomMostBlock();
        }

        BasicBlock* previous      = cur->Prev();
        BasicBlock* nextLoopBlock = lastNonLoopBlock->Next();
        assert(previous != nullptr);
        if (!BasicBlock::sameEHRegion(previous, nextLoopBlock) || !BasicBlock::sameEHRegion(previous, insertionPoint))
        {
            // EH regions would be ill-formed if we moved these blocks out.
            cur = nextLoopBlock;
            continue;
        }

        // Now physically move the blocks.
        fgUnlinkRange(cur, lastNonLoopBlock);
        fgMoveBlocksAfter(cur, lastNonLoopBlock, insertionPoint);
        ehUpdateLastBlocks(insertionPoint, lastNonLoopBlock);

        // Update insertionPoint for the next insertion.
        insertionPoint = lastNonLoopBlock;

        cur = nextLoopBlock;
    }
}

//-----------------------------------------------------------------------------
// optCreatePreheader: Create (or find) a preheader for a natural loop.
//
// Parameters:
//   loop - The loop to create the preheader for
//
// Returns:
//   True if a new preheader block had to be created.
//
bool Compiler::optCreatePreheader(FlowGraphNaturalLoop* loop)
{
    BasicBlock* header = loop->GetHeader();

    // If all loop backedges sources are within the same try region as the loop header,
    // then the preheader can be in the same try region as the header.
    //
    // Otherwise the preheader must be in the enclosing try region.
    //
    unsigned preheaderEHRegion    = EHblkDsc::NO_ENCLOSING_INDEX;
    bool     inSameRegionAsHeader = true;
    bool     headerIsTryEntry     = bbIsTryBeg(header);
    if (header->hasTryIndex())
    {
        preheaderEHRegion = header->getTryIndex();
        for (FlowEdge* backEdge : loop->BackEdges())
        {
            BasicBlock* const backedgeSource = backEdge->getSourceBlock();
            if (!bbInTryRegions(preheaderEHRegion, backedgeSource))
            {
                // Preheader should be in the true enclosing region of the header.
                //
                preheaderEHRegion    = ehTrueEnclosingTryIndex(preheaderEHRegion);
                inSameRegionAsHeader = false;
                break;
            }
        }
    }

    if (!bbIsHandlerBeg(header) && (loop->EntryEdges().size() == 1))
    {
        BasicBlock* preheaderCandidate = loop->EntryEdges()[0]->getSourceBlock();
        unsigned    candidateEHRegion =
            preheaderCandidate->hasTryIndex() ? preheaderCandidate->getTryIndex() : EHblkDsc::NO_ENCLOSING_INDEX;
        if (preheaderCandidate->KindIs(BBJ_ALWAYS) && preheaderCandidate->TargetIs(loop->GetHeader()) &&
            (candidateEHRegion == preheaderEHRegion))
        {
            JITDUMP("Natural loop " FMT_LP " already has preheader " FMT_BB "\n", loop->GetIndex(),
                    preheaderCandidate->bbNum);
            return false;
        }
    }

    BasicBlock* preheader = fgNewBBbefore(BBJ_ALWAYS, header, false);
    preheader->SetFlags(BBF_INTERNAL);

    if (inSameRegionAsHeader)
    {
        fgExtendEHRegionBefore(header);

        // If the header was a try region entry, it no longer is.
        //
        if (headerIsTryEntry)
        {
            assert(!bbIsTryBeg(header));
            header->RemoveFlags(BBF_DONT_REMOVE);
        }
    }
    else
    {
        fgSetEHRegionForNewPreheaderOrExit(preheader);
    }

    preheader->bbCodeOffs = header->bbCodeOffs;

    JITDUMP("Created new preheader " FMT_BB " for " FMT_LP "\n", preheader->bbNum, loop->GetIndex());

    FlowEdge* const newEdge = fgAddRefPred(header, preheader);
    preheader->SetTargetEdge(newEdge);

    for (FlowEdge* enterEdge : loop->EntryEdges())
    {
        BasicBlock* enterBlock = enterEdge->getSourceBlock();
        JITDUMP("Entry edge " FMT_BB " -> " FMT_BB " becomes " FMT_BB " -> " FMT_BB "\n", enterBlock->bbNum,
                header->bbNum, enterBlock->bbNum, preheader->bbNum);

        fgReplaceJumpTarget(enterBlock, header, preheader);
    }

    loop->SetEntryEdge(newEdge);

    optSetWeightForPreheaderOrExit(loop, preheader);

    if (preheader->hasProfileWeight() && preheader->hasEHBoundaryIn())
    {
        JITDUMP("optCreatePreheader: " FMT_BB
                " is not reachable via normal flow, so skip checking its entry weight. Data %s inconsistent.\n",
                preheader->bbNum, fgPgoConsistent ? "is now" : "was already");
        fgPgoConsistent = false;
    }

    return true;
}

//-----------------------------------------------------------------------------
// optSplitHeaderIfNecessary: If preheader and header are in different try
//  regions, split the header to put it into the same try region as the preheader
//
// Parameters:
//   loop - loop that may need header splitting
//
// Returns:
//   True if the header was split
//
// Notes:
//   Ensures that no loop header is also a try entry.
//
bool Compiler::optSplitHeaderIfNecessary(FlowGraphNaturalLoop* loop)
{
    BasicBlock* header    = loop->GetHeader();
    BasicBlock* preheader = loop->GetPreheader();

    if (BasicBlock::sameTryRegion(header, preheader))
    {
        assert(!bbIsTryBeg(header));
        return false;
    }

    // If the preheader and header are in different try regions,
    // the header should be a try entry.
    //
    assert(bbIsTryBeg(header));

    JITDUMP("Splitting " FMT_LP " header / try entry " FMT_BB "\n", loop->GetIndex(), header->bbNum);

    Statement* const firstStmt   = header->firstStmt();
    BasicBlock*      newTryEntry = nullptr;

    if (firstStmt == nullptr)
    {
        // Empty header
        //
        newTryEntry = fgSplitBlockAtEnd(header);
    }
    else
    {
        // Non-empty header.
        //
        Statement* const lastStmt      = header->lastStmt();
        bool const       hasTerminator = header->HasTerminator();
        Statement* const stopStmt      = hasTerminator ? lastStmt : nullptr;
        Statement*       splitBefore   = firstStmt;

        while ((splitBefore != stopStmt) && (splitBefore->GetRootNode()->gtFlags & (GTF_EXCEPT | GTF_CALL)) == 0)
        {
            splitBefore = splitBefore->GetNextStmt();
        }

        // If no statement can throw, split at the end, as long as there's no terminator
        //
        if (splitBefore == nullptr)
        {
            assert(!hasTerminator);
            newTryEntry = fgSplitBlockAtEnd(header);
        }
        // If the header has a single statement and needs a terminator, or the first statement
        // can throw, split at the beginning
        //
        else if (splitBefore == firstStmt)
        {
            newTryEntry = fgSplitBlockAtBeginning(header);
        }
        // Else split in the middle
        //
        else
        {
            newTryEntry = fgSplitBlockAfterStatement(header, splitBefore->GetPrevStmt());
        }
    }

    // update EH table, and keep track of the outermost enclosing try
    //
    EHblkDsc* outermostHBtab = nullptr;
    for (EHblkDsc* const HBtab : EHClauses(this))
    {
        if (HBtab->ebdTryBeg == header)
        {
            fgSetTryBeg(HBtab, newTryEntry);
            outermostHBtab = HBtab;
        }
    }
    assert(outermostHBtab != nullptr);

    // Recompute preheader placement
    //
    const unsigned enclosingTryIndex = outermostHBtab->ebdEnclosingTryIndex;

    if (enclosingTryIndex == EHblkDsc::NO_ENCLOSING_INDEX)
    {
        header->clearTryIndex();
    }
    else
    {
        header->setTryIndex(enclosingTryIndex);
    }

    assert(!bbIsTryBeg(header));
    return true;
}

//-----------------------------------------------------------------------------
// optCanonicalizeExits: Canonicalize all regular exits of the loop so that
// they have only loop predecessors.
//
// Parameters:
//   loop - The loop
//
// Returns:
//   True if any flow graph modifications were made.
//
bool Compiler::optCanonicalizeExits(FlowGraphNaturalLoop* loop)
{
    bool changed = false;

    for (FlowEdge* edge : loop->ExitEdges())
    {
        // Find all blocks outside the loop from this exiting block. Those
        // blocks are exits. Note that we may see preheaders created by
        // previous canonicalization here, which are not part of the DFS tree
        // or properly maintained in a parent loop. This also means the
        // destination block of the exit edge may no longer be right, so we
        // cannot use VisitRegularExitBlocks. The canonicalization here works
        // despite this.
        edge->getSourceBlock()->VisitRegularSuccs(this, [=, &changed](BasicBlock* succ) {
            if (!loop->ContainsBlock(succ))
            {
                changed |= optCanonicalizeExit(loop, succ);
            }

            return BasicBlockVisit::Continue;
        });
    }

    return changed;
}

//-----------------------------------------------------------------------------
// optCanonicalizeExit: Canonicalize a single exit block to have only loop
// predecessors.
//
// Parameters:
//   loop - The loop
//
// Returns:
//   True if any flow graph modifications were made.
//
bool Compiler::optCanonicalizeExit(FlowGraphNaturalLoop* loop, BasicBlock* exit)
{
    assert(!loop->ContainsBlock(exit));

    if (bbIsHandlerBeg(exit))
    {
        return false;
    }

    bool allLoopPreds = true;
    for (BasicBlock* pred : exit->PredBlocks())
    {
        if (!loop->ContainsBlock(pred))
        {
            allLoopPreds = false;
            break;
        }
    }

    if (allLoopPreds)
    {
        // Already canonical
        JITDUMP("All preds of exit " FMT_BB " of " FMT_LP " are already in the loop, no exit canonicalization needed\n",
                exit->bbNum, loop->GetIndex());
        return false;
    }

    BasicBlock* newExit;

    JITDUMP("Canonicalize exit " FMT_BB " for " FMT_LP " to have only loop predecessors\n", exit->bbNum,
            loop->GetIndex());

    if (UsesCallFinallyThunks() && exit->KindIs(BBJ_CALLFINALLY))
    {
        // Branches to a BBJ_CALLFINALLY _must_ come from inside its associated
        // try region, and when we have callfinally thunks the BBJ_CALLFINALLY
        // is outside it. Thus, insert newExit at the end of the finally's
        // try region.
        BasicBlock* finallyBlock = exit->GetTarget();
        assert(finallyBlock->hasHndIndex());
        newExit = fgNewBBatTryRegionEnd(BBJ_ALWAYS, finallyBlock->getHndIndex());
    }
    else
    {
        newExit = fgNewBBbefore(BBJ_ALWAYS, exit, false);
        fgSetEHRegionForNewPreheaderOrExit(newExit);
    }

    newExit->SetFlags(BBF_INTERNAL);

    FlowEdge* const newEdge = fgAddRefPred(exit, newExit);
    newExit->SetTargetEdge(newEdge);

    newExit->bbCodeOffs = exit->bbCodeOffs;

    for (BasicBlock* pred : exit->PredBlocksEditing())
    {
        if (loop->ContainsBlock(pred))
        {
            fgReplaceJumpTarget(pred, exit, newExit);
        }
    }

    optSetWeightForPreheaderOrExit(loop, newExit);

    JITDUMP("Created new exit " FMT_BB " to replace " FMT_BB " exit for " FMT_LP "\n", newExit->bbNum, exit->bbNum,
            loop->GetIndex());
    return true;
}

//-----------------------------------------------------------------------------
// optSetWeightForPreheaderOrExit: Set the weight of a newly created preheader
// or exit, after it has been added to the flowgraph.
//
// Parameters:
//   loop  - The loop
//   block - The new preheader or exit block
//
void Compiler::optSetWeightForPreheaderOrExit(FlowGraphNaturalLoop* loop, BasicBlock* block)
{
    bool     hasProfWeight = true;
    weight_t newWeight     = BB_ZERO_WEIGHT;

    for (FlowEdge* const edge : block->PredEdges())
    {
        newWeight += edge->getLikelyWeight();
        hasProfWeight &= edge->getSourceBlock()->hasProfileWeight();
    }

    block->bbWeight = newWeight;

    if (hasProfWeight)
    {
        block->SetFlags(BBF_PROF_WEIGHT);
    }
    else
    {
        block->RemoveFlags(BBF_PROF_WEIGHT);
    }
}

/*****************************************************************************
 *
 *  See if the given tree can be computed in the given precision (which must
 *  be smaller than the type of the tree for this to make sense). If 'doit'
 *  is false, we merely check to see whether narrowing is possible; if we
 *  get called with 'doit' being true, we actually perform the narrowing.
 */

bool Compiler::optNarrowTree(GenTree* tree, var_types srct, var_types dstt, ValueNumPair vnpNarrow, bool doit)
{
    genTreeOps oper;
    unsigned   kind;

    noway_assert(tree);
    noway_assert(genActualType(tree->gtType) == genActualType(srct));

    /* Assume we're only handling integer types */
    noway_assert(varTypeIsIntegral(srct));
    noway_assert(varTypeIsIntegral(dstt));

    unsigned srcSize = genTypeSize(srct);
    unsigned dstSize = genTypeSize(dstt);

    /* dstt must be smaller than srct to narrow */
    if (dstSize >= srcSize)
    {
        return false;
    }

    /* Figure out what kind of a node we have */
    oper = tree->OperGet();
    kind = tree->OperKind();

    ValueNumPair NoVNPair = ValueNumPair();

    if (kind & GTK_LEAF)
    {
        switch (oper)
        {
            /* Constants can usually be narrowed by changing their value */

#ifndef TARGET_64BIT
            int64_t lval;
            int64_t lmask;

            case GT_CNS_LNG:
                lval  = tree->AsIntConCommon()->LngValue();
                lmask = 0;

                switch (dstt)
                {
                    case TYP_BYTE:
                        lmask = 0x0000007F;
                        break;
                    case TYP_UBYTE:
                        lmask = 0x000000FF;
                        break;
                    case TYP_SHORT:
                        lmask = 0x00007FFF;
                        break;
                    case TYP_USHORT:
                        lmask = 0x0000FFFF;
                        break;
                    case TYP_INT:
                        lmask = 0x7FFFFFFF;
                        break;
                    case TYP_UINT:
                        lmask = 0xFFFFFFFF;
                        break;

                    default:
                        return false;
                }

                if ((lval & lmask) != lval)
                    return false;

                if (doit)
                {
                    tree->BashToConst(static_cast<int32_t>(lval));
                    fgUpdateConstTreeValueNumber(tree);
                }

                return true;
#endif

            case GT_CNS_INT:

                ssize_t ival;
                ival = tree->AsIntCon()->gtIconVal;
                ssize_t imask;
                imask = 0;

                switch (dstt)
                {
                    case TYP_BYTE:
                        imask = 0x0000007F;
                        break;
                    case TYP_UBYTE:
                        imask = 0x000000FF;
                        break;
                    case TYP_SHORT:
                        imask = 0x00007FFF;
                        break;
                    case TYP_USHORT:
                        imask = 0x0000FFFF;
                        break;
#ifdef TARGET_64BIT
                    case TYP_INT:
                        imask = 0x7FFFFFFF;
                        break;
                    case TYP_UINT:
                        imask = 0xFFFFFFFF;
                        break;
#endif // TARGET_64BIT
                    default:
                        return false;
                }

                if ((ival & imask) != ival)
                {
                    return false;
                }

#ifdef TARGET_64BIT
                if (doit)
                {
                    tree->gtType                = TYP_INT;
                    tree->AsIntCon()->gtIconVal = (int)ival;

                    fgUpdateConstTreeValueNumber(tree);
                }
#endif // TARGET_64BIT

                return true;

                /* Operands that are in memory can usually be narrowed
                   simply by changing their gtType */

            case GT_LCL_VAR:
                /* We only allow narrowing long -> int for a GT_LCL_VAR */
                if (dstSize == sizeof(int))
                {
                    goto NARROW_IND;
                }
                break;

            case GT_LCL_FLD:
                goto NARROW_IND;
            default:
                break;
        }

        noway_assert(doit == false);
        return false;
    }

    if (kind & (GTK_BINOP | GTK_UNOP))
    {
        GenTree* op1;
        op1 = tree->AsOp()->gtOp1;
        GenTree* op2;
        op2 = tree->AsOp()->gtOp2;

        switch (tree->gtOper)
        {
            case GT_AND:
                noway_assert(genActualType(tree->gtType) == genActualType(op1->gtType));
                noway_assert(genActualType(tree->gtType) == genActualType(op2->gtType));

                GenTree* opToNarrow;
                opToNarrow = nullptr;
                GenTree** otherOpPtr;
                otherOpPtr = nullptr;
                bool foundOperandThatBlocksNarrowing;
                foundOperandThatBlocksNarrowing = false;

                // If 'dstt' is unsigned and one of the operands can be narrowed into 'dsst',
                // the result of the GT_AND will also fit into 'dstt' and can be narrowed.
                // The same is true if one of the operands is an int const and can be narrowed into 'dsst'.
                if (op2->OperIs(GT_CNS_INT) || varTypeIsUnsigned(dstt))
                {
                    if (optNarrowTree(op2, srct, dstt, NoVNPair, false))
                    {
                        opToNarrow = op2;
                        otherOpPtr = &tree->AsOp()->gtOp1;
                    }
                    else
                    {
                        foundOperandThatBlocksNarrowing = true;
                    }
                }

                if ((opToNarrow == nullptr) && (op1->OperIs(GT_CNS_INT) || varTypeIsUnsigned(dstt)))
                {
                    if (optNarrowTree(op1, srct, dstt, NoVNPair, false))
                    {
                        opToNarrow = op1;
                        otherOpPtr = &tree->AsOp()->gtOp2;
                    }
                    else
                    {
                        foundOperandThatBlocksNarrowing = true;
                    }
                }

                if (opToNarrow != nullptr)
                {
                    // We will change the type of the tree and narrow opToNarrow
                    //
                    if (doit)
                    {
                        tree->gtType = genActualType(dstt);
                        tree->SetVNs(vnpNarrow);

                        optNarrowTree(opToNarrow, srct, dstt, NoVNPair, true);
                        // We may also need to cast away the upper bits of *otherOpPtr
                        if (srcSize == 8)
                        {
                            assert(tree->TypeIs(TYP_INT));
                            GenTree* castOp = gtNewCastNode(TYP_INT, *otherOpPtr, false, TYP_INT);
                            castOp->SetMorphed(this);
                            *otherOpPtr = castOp;
                        }
                    }
                    return true;
                }

                if (foundOperandThatBlocksNarrowing)
                {
                    noway_assert(doit == false);
                    return false;
                }

                goto COMMON_BINOP;

            case GT_ADD:
            case GT_MUL:

                if (tree->gtOverflow() || varTypeIsSmall(dstt))
                {
                    noway_assert(doit == false);
                    return false;
                }
                FALLTHROUGH;

            case GT_OR:
            case GT_XOR:
                noway_assert(genActualType(tree->gtType) == genActualType(op1->gtType));
                noway_assert(genActualType(tree->gtType) == genActualType(op2->gtType));
            COMMON_BINOP:
                if (!optNarrowTree(op1, srct, dstt, NoVNPair, doit) || !optNarrowTree(op2, srct, dstt, NoVNPair, doit))
                {
                    noway_assert(doit == false);
                    return false;
                }

                /* Simply change the type of the tree */

                if (doit)
                {
                    if (tree->OperIs(GT_MUL) && (tree->gtFlags & GTF_MUL_64RSLT))
                    {
                        tree->gtFlags &= ~GTF_MUL_64RSLT;
                    }

                    tree->gtType = genActualType(dstt);
                    tree->SetVNs(vnpNarrow);
                }

                return true;

            case GT_IND:

            NARROW_IND:

                if ((dstSize > genTypeSize(tree->gtType)) &&
                    (varTypeIsUnsigned(dstt) && !varTypeIsUnsigned(tree->gtType)))
                {
                    return false;
                }

                /* Simply change the type of the tree */

                if (doit && (dstSize <= genTypeSize(tree->gtType)))
                {
                    if (!varTypeIsSmall(dstt))
                    {
                        dstt = varTypeToSigned(dstt);
                    }

                    tree->gtType = dstt;
                    tree->SetVNs(vnpNarrow);
                }

                return true;

            case GT_EQ:
            case GT_NE:
            case GT_LT:
            case GT_LE:
            case GT_GT:
            case GT_GE:

                /* These can always be narrowed since they only represent 0 or 1 */
                return true;

            case GT_CAST:
            {
#ifdef DEBUG
                if ((tree->gtDebugFlags & GTF_DEBUG_CAST_DONT_FOLD) != 0)
                {
                    return false;
                }
#endif

                if ((tree->CastToType() != srct) || tree->gtOverflow())
                {
                    return false;
                }

                if (varTypeIsInt(op1) && varTypeIsInt(dstt) && tree->TypeIs(TYP_LONG))
                {
                    // We have a CAST that converts into to long while dstt is int.
                    // so we can just convert the cast to int -> int and someone will clean it up.
                    if (doit)
                    {
                        tree->CastToType() = TYP_INT;
                        tree->ChangeType(TYP_INT);
                        tree->ClearUnsigned();
                    }
                    return true;
                }
            }
                return false;

            case GT_COMMA:
                if (optNarrowTree(op2, srct, dstt, vnpNarrow, doit))
                {
                    /* Simply change the type of the tree */

                    if (doit)
                    {
                        tree->gtType = genActualType(dstt);
                        tree->SetVNs(vnpNarrow);
                    }
                    return true;
                }
                return false;

            default:
                noway_assert(doit == false);
                return false;
        }
    }

    return false;
}

//------------------------------------------------------------------------
// optRecordSsaUses: note any SSA uses within tree
//
// Arguments:
//   tree     - tree to examine
//   block    - block that does (or will) contain tree
//
// Notes:
//   Ignores SSA defs. We assume optimizations that modify trees with
//   SSA defs are introducing new defs for locals that do not require PHIs
//   or updating existing defs in place.
//
//   Currently does not examine PHI_ARG nodes as no opt phases introduce new PHIs.
//
//   Assumes block is a block that was rewritten by SSA or introduced post-SSA
//   (in particular, block is not unreachable).
//
void Compiler::optRecordSsaUses(GenTree* tree, BasicBlock* block)
{
    class SsaRecordingVisitor : public GenTreeVisitor<SsaRecordingVisitor>
    {
    private:
        BasicBlock* const m_block;

    public:
        enum
        {
            DoPreOrder    = true,
            DoLclVarsOnly = true
        };

        SsaRecordingVisitor(Compiler* compiler, BasicBlock* block)
            : GenTreeVisitor<SsaRecordingVisitor>(compiler)
            , m_block(block)
        {
        }

        Compiler::fgWalkResult PreOrderVisit(GenTree** use, GenTree* user)
        {
            GenTreeLclVarCommon* const tree  = (*use)->AsLclVarCommon();
            const bool                 isUse = (tree->gtFlags & GTF_VAR_DEF) == 0;

            if (isUse)
            {
                if (tree->HasSsaName())
                {
                    unsigned const      lclNum    = tree->GetLclNum();
                    unsigned const      ssaNum    = tree->GetSsaNum();
                    LclVarDsc* const    varDsc    = m_compiler->lvaGetDesc(lclNum);
                    LclSsaVarDsc* const ssaVarDsc = varDsc->GetPerSsaData(ssaNum);
                    ssaVarDsc->AddUse(m_block);
                }
                else
                {
                    assert(!m_compiler->lvaInSsa(tree->GetLclNum()));
                    assert(!tree->HasCompositeSsaName());
                }
            }

            return fgWalkResult::WALK_CONTINUE;
        }
    };

    SsaRecordingVisitor srv(this, block);
    srv.WalkTree(&tree, nullptr);
}

//------------------------------------------------------------------------
// optPerformHoistExpr: hoist an expression into the preheader of a loop
//
// Arguments:
//   origExpr - tree to hoist
//   exprBb   - block containing the tree
//   loop     - loop that we're hoisting origExpr out of
//
void Compiler::optPerformHoistExpr(GenTree* origExpr, BasicBlock* exprBb, FlowGraphNaturalLoop* loop)
{
    assert(exprBb != nullptr);
    assert(loop->EntryEdges().size() == 1);

    BasicBlock* preheader = loop->EntryEdge(0)->getSourceBlock();
#ifdef DEBUG
    if (verbose)
    {
        printf("\nHoisting a copy of ");
        printTreeID(origExpr);
        printf(" " FMT_VN, origExpr->gtVNPair.GetLiberal());
        printf(" from " FMT_BB " into PreHeader " FMT_BB " for loop " FMT_LP " (head: " FMT_BB "):\n", exprBb->bbNum,
               preheader->bbNum, loop->GetIndex(), loop->GetHeader()->bbNum);
        gtDispTree(origExpr);
        printf("\n");
    }
#endif

    // Create a copy of the expression and mark it for CSE's.
    GenTree* hoistExpr = gtCloneExpr(origExpr);

    // The hoist Expr does not have to computed into a specific register,
    // so clear the RegNum if it was set in the original expression
    hoistExpr->ClearRegNum();

    // Copy any loop memory dependence.
    optCopyLoopMemoryDependence(origExpr, hoistExpr);

    // At this point we should have a cloned expression
    hoistExpr->gtFlags |= GTF_MAKE_CSE;
    assert(hoistExpr != origExpr);

    // The value of the expression isn't used.
    GenTree* hoist = gtUnusedValNode(hoistExpr);

    // Scan the tree for any new SSA uses.
    //
    optRecordSsaUses(hoist, preheader);

    preheader->CopyFlags(exprBb, BBF_COPY_PROPAGATE);

    fgInsertStmtAtEnd(preheader, fgNewStmtFromTree(hoist));

#ifdef DEBUG
    if (verbose)
    {
        printf("This hoisted copy placed in PreHeader (" FMT_BB "):\n", preheader->bbNum);
        gtDispTree(hoist);
        printf("\n");
    }
#endif

#ifdef DEBUG
    if (m_nodeTestData != nullptr)
    {

        // What is the depth of the loop "lnum"?
        ssize_t depth = loop->GetDepth();

        NodeToTestDataMap* testData = GetNodeTestData();

        TestLabelAndNum tlAndN;
        if (testData->Lookup(origExpr, &tlAndN) && tlAndN.m_tl == TL_LoopHoist)
        {
            if (tlAndN.m_num == -1)
            {
                printf("Node ");
                printTreeID(origExpr);
                printf(" was declared 'do not hoist', but is being hoisted.\n");
                assert(false);
            }
            else if (tlAndN.m_num != depth)
            {
                printf("Node ");
                printTreeID(origExpr);
                printf(" was declared as hoistable from loop at nesting depth %d; actually hoisted from loop at depth "
                       "%d.\n",
                       tlAndN.m_num, depth);
                assert(false);
            }
            else
            {
                // We've correctly hoisted this, so remove the annotation.  Later, we'll check for any remaining "must
                // hoist" annotations.
                testData->Remove(origExpr);
                // Now we insert an annotation to make sure that "hoistExpr" is actually CSE'd.
                tlAndN.m_tl  = TL_CSE_Def;
                tlAndN.m_num = m_loopHoistCSEClass++;
                testData->Set(hoistExpr, tlAndN);
            }
        }
    }
#endif

#if LOOP_HOIST_STATS
    if (!m_curLoopHasHoistedExpression)
    {
        m_loopsWithHoistedExpressions++;
        m_curLoopHasHoistedExpression = true;
    }
    m_totalHoistedExpressions++;
#endif // LOOP_HOIST_STATS
}

//------------------------------------------------------------------------
// optHoistLoopCode: run loop hoisting phase
//
// Returns:
//    suitable phase status
//
PhaseStatus Compiler::optHoistLoopCode()
{
    // If we don't have any loops in the method then take an early out now.
    if (m_loops->NumLoops() == 0)
    {
        JITDUMP("\nNo loops; no hoisting\n");
        return PhaseStatus::MODIFIED_NOTHING;
    }

#ifdef DEBUG
    unsigned jitNoHoist = JitConfig.JitNoHoist();
    if (jitNoHoist > 0)
    {
        JITDUMP("\nJitNoHoist set; no hoisting\n");
        return PhaseStatus::MODIFIED_NOTHING;
    }
#endif

#ifdef DEBUG
    if (verbose)
    {
        printf("\n*************** In optHoistLoopCode()\n");
        fgDispHandlerTab();
    }
#endif

    optComputeInterestingVarSets();

    // Consider all the loops, visiting child loops first.
    //
    bool             modified = false;
    LoopHoistContext hoistCtxt(this);
    for (FlowGraphNaturalLoop* loop : m_loops->InPostOrder())
    {
#if LOOP_HOIST_STATS
        // Record stats
        m_curLoopHasHoistedExpression = false;
        m_loopsConsidered++;
#endif // LOOP_HOIST_STATS

        modified |= optHoistThisLoop(loop, &hoistCtxt);
    }

#ifdef DEBUG
    // Test Data stuff..
    //
    if (m_nodeTestData != nullptr)
    {
        NodeToTestDataMap* testData = GetNodeTestData();
        for (GenTree* const node : NodeToTestDataMap::KeyIteration(testData))
        {
            TestLabelAndNum tlAndN;
            bool            b = testData->Lookup(node, &tlAndN);
            assert(b);
            if (tlAndN.m_tl != TL_LoopHoist)
            {
                continue;
            }
            // Otherwise, it is a loop hoist annotation.
            assert(tlAndN.m_num < 100); // >= 100 indicates nested static field address, should already have been moved.
            if (tlAndN.m_num >= 0)
            {
                printf("Node ");
                printTreeID(node);
                printf(" was declared 'must hoist', but has not been hoisted.\n");
                assert(false);
            }
        }
    }
#endif // DEBUG

    return modified ? PhaseStatus::MODIFIED_EVERYTHING : PhaseStatus::MODIFIED_NOTHING;
}

//------------------------------------------------------------------------
// optHoistThisLoop: run loop hoisting for the indicated loop
//
// Arguments:
//    loop - loop to process
//    hoistCtxt - context for the hoisting
//
// Returns:
//    true if any hoisting was done
//
bool Compiler::optHoistThisLoop(FlowGraphNaturalLoop* loop, LoopHoistContext* hoistCtxt)
{
    // Ensure the per-loop sets/tables are empty.
    hoistCtxt->m_curLoopVnInvariantCache.RemoveAll();

    const LoopSideEffects& sideEffs = m_loopSideEffects[loop->GetIndex()];

#ifdef DEBUG
    if (verbose)
    {
        printf("optHoistThisLoop processing ");
        FlowGraphNaturalLoop::Dump(loop);
        printf("  Loop body %s a call\n", sideEffs.ContainsCall ? "contains" : "does not contain");
    }
#endif

    VARSET_TP loopVars(VarSetOps::Intersection(this, sideEffs.VarInOut, sideEffs.VarUseDef));

    hoistCtxt->m_loopVarInOutCount = VarSetOps::Count(this, sideEffs.VarInOut);
    hoistCtxt->m_loopVarCount      = VarSetOps::Count(this, loopVars);
    hoistCtxt->m_hoistedExprCount  = 0;

#ifndef TARGET_64BIT

    if (!VarSetOps::IsEmpty(this, lvaLongVars))
    {
        // Since 64-bit variables take up two registers on 32-bit targets, we increase
        //  the Counts such that each TYP_LONG variable counts twice.
        //
        VARSET_TP loopLongVars(VarSetOps::Intersection(this, loopVars, lvaLongVars));
        VARSET_TP inOutLongVars(VarSetOps::Intersection(this, sideEffs.VarInOut, lvaLongVars));

#ifdef DEBUG
        if (verbose)
        {
            printf("\n  LONGVARS(%d)=", VarSetOps::Count(this, lvaLongVars));
            dumpConvertedVarSet(this, lvaLongVars);
        }
#endif
        hoistCtxt->m_loopVarCount += VarSetOps::Count(this, loopLongVars);
        hoistCtxt->m_loopVarInOutCount += VarSetOps::Count(this, inOutLongVars);
    }
#endif // !TARGET_64BIT

#ifdef DEBUG
    if (verbose)
    {
        printf("\n  USEDEF  (%d)=", VarSetOps::Count(this, sideEffs.VarUseDef));
        dumpConvertedVarSet(this, sideEffs.VarUseDef);

        printf("\n  INOUT   (%d)=", hoistCtxt->m_loopVarInOutCount);
        dumpConvertedVarSet(this, sideEffs.VarInOut);

        printf("\n  LOOPVARS(%d)=", hoistCtxt->m_loopVarCount);
        dumpConvertedVarSet(this, loopVars);
        printf("\n");
    }
#endif

    if (!VarSetOps::IsEmpty(this, lvaFloatVars))
    {
        VARSET_TP loopFPVars(VarSetOps::Intersection(this, loopVars, lvaFloatVars));
        VARSET_TP inOutFPVars(VarSetOps::Intersection(this, sideEffs.VarInOut, lvaFloatVars));

        hoistCtxt->m_loopVarFPCount      = VarSetOps::Count(this, loopFPVars);
        hoistCtxt->m_loopVarInOutFPCount = VarSetOps::Count(this, inOutFPVars);
        hoistCtxt->m_hoistedFPExprCount  = 0;
        hoistCtxt->m_loopVarCount -= hoistCtxt->m_loopVarFPCount;
        hoistCtxt->m_loopVarInOutCount -= hoistCtxt->m_loopVarInOutFPCount;

#ifdef DEBUG
        if (verbose)
        {
            printf("  INOUT-FP(%d)=", hoistCtxt->m_loopVarInOutFPCount);
            dumpConvertedVarSet(this, inOutFPVars);

            printf("\n  LOOPV-FP(%d)=", hoistCtxt->m_loopVarFPCount);
            dumpConvertedVarSet(this, loopFPVars);

            printf("\n");
        }
#endif
    }
    else // lvaFloatVars is empty
    {
        hoistCtxt->m_loopVarFPCount      = 0;
        hoistCtxt->m_loopVarInOutFPCount = 0;
        hoistCtxt->m_hoistedFPExprCount  = 0;
    }

#ifdef FEATURE_MASKED_HW_INTRINSICS
    if (!VarSetOps::IsEmpty(this, lvaMaskVars))
    {
        VARSET_TP loopMskVars(VarSetOps::Intersection(this, loopVars, lvaMaskVars));
        VARSET_TP inOutMskVars(VarSetOps::Intersection(this, sideEffs.VarInOut, lvaMaskVars));

        hoistCtxt->m_loopVarMskCount      = VarSetOps::Count(this, loopMskVars);
        hoistCtxt->m_loopVarInOutMskCount = VarSetOps::Count(this, inOutMskVars);
        hoistCtxt->m_hoistedMskExprCount  = 0;
        hoistCtxt->m_loopVarCount -= hoistCtxt->m_loopVarMskCount;
        hoistCtxt->m_loopVarInOutCount -= hoistCtxt->m_loopVarInOutMskCount;

#ifdef DEBUG
        if (verbose)
        {
            printf("  INOUT-MSK(%d)=", hoistCtxt->m_loopVarInOutMskCount);
            dumpConvertedVarSet(this, inOutMskVars);

            printf("\n  LOOPV-MSK(%d)=", hoistCtxt->m_loopVarMskCount);
            dumpConvertedVarSet(this, loopMskVars);

            printf("\n");
        }
#endif
    }
    else // lvaMaskVars is empty
    {
        hoistCtxt->m_loopVarMskCount      = 0;
        hoistCtxt->m_loopVarInOutMskCount = 0;
        hoistCtxt->m_hoistedMskExprCount  = 0;
    }
#endif // FEATURE_MASKED_HW_INTRINSICS

    // Find the set of definitely-executed blocks.
    // Ideally, the definitely-executed blocks are the ones that post-dominate the entry block.
    // Until we have post-dominators, we'll special-case for single-exit blocks.
    //
    // Todo: it is not clear if this is a correctness requirement or a profitability heuristic.
    // It seems like the latter. Ideally there are enough safeguards to prevent hoisting exception
    // or side-effect dependent things. Note that HoistVisitor uses `m_beforeSideEffect` to determine if it's
    // ok to hoist a side-effect. It allows this only for the first block (the entry block), before any
    // side-effect has been seen. After the first block, it assumes that there has been a side effect and
    // no further side-effect can be hoisted. It is true that we don't analyze any program behavior in the
    // flow graph between the entry block and the subsequent blocks, whether they be the next block dominating
    // the exit block, or the pre-headers of nested loops.
    //
    // We really should consider hoisting from conditionally executed blocks, if they are frequently executed
    // and it is safe to evaluate the tree early.
    //
    assert(m_dfsTree != nullptr);
    BitVecTraits traits(m_dfsTree->PostOrderTraits());
    BitVec       defExec(BitVecOps::MakeEmpty(&traits));

    // Add the pre-headers of any child loops to the list of blocks to consider for hoisting.
    // Note that these are not necessarily definitely executed. However, it is a heuristic that they will
    // often provide good opportunities for further hoisting since we hoist from inside-out,
    // and the inner loop may have already hoisted something loop-invariant to them. If the child
    // loop pre-header block would be added anyway (by dominating the loop exit block), we don't
    // add it here, and let it be added naturally, below.
    //
    // Note that all pre-headers get added first, which means they get considered for hoisting last. It is
    // assumed that the order does not matter for correctness.
    // Note that the order does matter for the hoisting profitability heuristics, as we might
    // run out of hoisting budget when processing the blocks.
    //
    // For example, consider this loop nest:
    //
    // for (....) { // loop L00
    //    pre-header 1
    //    for (...) { // loop L01
    //    }
    //    // pre-header 2
    //    for (...) { // loop L02
    //       // pre-header 3
    //       for (...) { // loop L03
    //       }
    //    }
    // }
    //
    // The order in the siblink links is RPO, so the loop below will push pre-header 1, then pre-header 2.
    // Then we will push the loop exit block, any IDom tree blocks leading to the header block, and finally
    // the header block itself. optHoistLoopBlocks performs hoisting in reverse, so we will hoist the header
    // block first and the pre-headers last.
    //
    // Note that pre-header 3 is not pushed, since it is not a direct child. It would have been processed
    // when loop L02 was considered for hoisting.

    for (FlowGraphNaturalLoop* childLoop = loop->GetChild(); childLoop != nullptr; childLoop = childLoop->GetSibling())
    {
        assert(childLoop->EntryEdges().size() == 1);
        BasicBlock* childPreHead = childLoop->EntryEdge(0)->getSourceBlock();
        if (loop->ExitEdges().size() == 1)
        {
            if (m_domTree->Dominates(childPreHead, loop->ExitEdges()[0]->getSourceBlock()))
            {
                // If the child loop pre-header dominates the exit, it will get added in the dominator tree
                // loop below.
                continue;
            }
        }
        else
        {
            // If the child loop pre-header is the loop entry for a multi-exit loop, it will get added below.
            if (childPreHead == loop->GetHeader())
            {
                continue;
            }
        }
        JITDUMP("  --  " FMT_BB " (child loop pre-header)\n", childPreHead->bbNum);
        BitVecOps::AddElemD(&traits, defExec, childPreHead->bbPostorderNum);
    }

    if (loop->ExitEdges().size() == 1)
    {
        BasicBlock* exiting = loop->ExitEdges()[0]->getSourceBlock();
        JITDUMP("  Considering hoisting in blocks that either dominate exit block " FMT_BB
                ", or pre-headers of nested loops, if any:\n",
                exiting->bbNum);

        // Push dominators, until we reach the header or exit the loop.
        //
        // Note that there is a mismatch between the dominator tree dominance
        // and loop header dominance; the dominator tree dominance relation
        // guarantees that a block A that dominates B was exited before B is
        // entered, meaning it could not possibly have thrown an exception. On
        // the other hand loop finding guarantees only that the header was
        // entered before other blocks in the loop. If the header is a
        // try-begin then blocks inside the catch may not necessarily be fully
        // dominated by the header, but may still be part of the loop.
        //
        BasicBlock* cur = exiting;
        while ((cur != nullptr) && (cur != loop->GetHeader()) && loop->ContainsBlock(cur))
        {
            JITDUMP("  --  " FMT_BB " (dominate exit block)\n", cur->bbNum);
            BitVecOps::AddElemD(&traits, defExec, cur->bbPostorderNum);
            cur = cur->bbIDom;
        }

        assert((cur == loop->GetHeader()) || bbIsTryBeg(loop->GetHeader()));
    }
    else // More than one exit
    {
        // We'll assume that only the entry block is definitely executed.
        // We could in the future do better.

        JITDUMP("  Considering hoisting in entry block " FMT_BB " because " FMT_LP " has more than one exit\n",
                loop->GetHeader()->bbNum, loop->GetIndex());
    }

    JITDUMP("  --  " FMT_BB " (header block)\n", loop->GetHeader()->bbNum);
    BitVecOps::AddElemD(&traits, defExec, loop->GetHeader()->bbPostorderNum);

    optHoistLoopBlocks(loop, &traits, defExec, hoistCtxt);

    unsigned numHoisted = hoistCtxt->m_hoistedFPExprCount + hoistCtxt->m_hoistedExprCount;
#ifdef FEATURE_MASKED_HW_INTRINSICS
    numHoisted += hoistCtxt->m_hoistedMskExprCount;
#endif // FEATURE_MASKED_HW_INTRINSICS
    return numHoisted > 0;
}

bool Compiler::optIsProfitableToHoistTree(GenTree*              tree,
                                          FlowGraphNaturalLoop* loop,
                                          LoopHoistContext*     hoistCtxt,
                                          bool                  defExecuted)
{
    bool loopContainsCall = m_loopSideEffects[loop->GetIndex()].ContainsCall;

    int availRegCount;
    int hoistedExprCount;
    int loopVarCount;
    int varInOutCount;

    if (varTypeUsesIntReg(tree))
    {
        hoistedExprCount = hoistCtxt->m_hoistedExprCount;
        loopVarCount     = hoistCtxt->m_loopVarCount;
        varInOutCount    = hoistCtxt->m_loopVarInOutCount;

        availRegCount = CNT_CALLEE_SAVED - 1;
        if (!loopContainsCall)
        {
            availRegCount += CNT_CALLEE_TRASH - 1;
        }
#ifndef TARGET_64BIT
        // For our 32-bit targets Long types take two registers.
        if (varTypeIsLong(tree->TypeGet()))
        {
            availRegCount = (availRegCount + 1) / 2;
        }
#endif
    }
#ifdef FEATURE_MASKED_HW_INTRINSICS
    else if (varTypeUsesMaskReg(tree))
    {
        hoistedExprCount = hoistCtxt->m_hoistedMskExprCount;
        loopVarCount     = hoistCtxt->m_loopVarMskCount;
        varInOutCount    = hoistCtxt->m_loopVarInOutMskCount;

        availRegCount = CNT_CALLEE_SAVED_MASK;
        if (!loopContainsCall)
        {
            availRegCount += CNT_CALLEE_TRASH_MASK - 1;
        }
    }
#endif // FEATURE_MASKED_HW_INTRINSICS
    else
    {
        assert(varTypeUsesFloatReg(tree));

        hoistedExprCount = hoistCtxt->m_hoistedFPExprCount;
        loopVarCount     = hoistCtxt->m_loopVarFPCount;
        varInOutCount    = hoistCtxt->m_loopVarInOutFPCount;

        availRegCount = CNT_CALLEE_SAVED_FLOAT;
        if (!loopContainsCall)
        {
            availRegCount += CNT_CALLEE_TRASH_FLOAT - 1;
        }
#ifdef TARGET_ARM
        // For ARM each double takes two FP registers
        // For now on ARM we won't track singles/doubles
        // and instead just assume that we always have doubles.
        //
        availRegCount /= 2;
#endif
    }

    // decrement the availRegCount by the count of expression that we have already hoisted.
    availRegCount -= hoistedExprCount;

    // the variables that are read/written inside the loop should
    // always be a subset of the InOut variables for the loop
    assert(loopVarCount <= varInOutCount);

    // If this tree isn't guaranteed to execute every loop iteration,
    // consider hoisting it only if it is expensive.
    //
    if (!defExecuted && (tree->GetCostEx() < (IND_COST_EX * 16)))
    {
        return false;
    }

    // When loopVarCount >= availRegCount we believe that all of the
    // available registers will get used to hold LclVars inside the loop.
    // This pessimistically assumes that each loopVar has a conflicting
    // lifetime with every other loopVar.
    // For this case we will hoist the expression only if is profitable
    // to place it in a stack home location (GetCostEx() >= 2*IND_COST_EX)
    // as we believe it will be placed in the stack or one of the other
    // loopVars will be spilled into the stack
    //
    if (loopVarCount >= availRegCount)
    {
        // Don't hoist expressions that are not heavy: tree->GetCostEx() < (2*IND_COST_EX)
        if (tree->GetCostEx() < (2 * IND_COST_EX))
        {
            JITDUMP("    tree cost too low: %d < %d (loopVarCount %u >= availRegCount %u)\n", tree->GetCostEx(),
                    2 * IND_COST_EX, loopVarCount, availRegCount);
            return false;
        }
    }

    // When varInOutCount < availRegCount we are know that there are
    // some available register(s) when we enter the loop body.
    // When varInOutCount == availRegCount there often will be a register
    // available when we enter the loop body, since a loop often defines a
    // LclVar on exit or there is often at least one LclVar that is worth
    // spilling to the stack to make way for this hoisted expression.
    // So we are willing hoist an expression with GetCostEx() == MIN_CSE_COST
    //
    if (varInOutCount > availRegCount)
    {
        // Don't hoist expressions that barely meet CSE cost requirements: tree->GetCostEx() == MIN_CSE_COST
        if (tree->GetCostEx() <= MIN_CSE_COST + 1)
        {
            JITDUMP("    tree not good CSE: %d <= %d (varInOutCount %u > availRegCount %u)\n", tree->GetCostEx(),
                    2 * MIN_CSE_COST + 1, varInOutCount, availRegCount)
            return false;
        }
    }

    return true;
}

//------------------------------------------------------------------------
// optRecordLoopMemoryDependence: record that tree's value number
//   is dependent on a particular memory VN
//
// Arguments:
//   tree -- tree in question
//   block -- block containing tree
//   memoryVN -- VN for a "map" from a select operation encounterd
//     while computing the tree's VN
//
// Notes:
//   Only tracks trees in loops, and memory updates in the same loop nest.
//   So this is a coarse-grained dependence that is only usable for
//   hoisting tree out of its enclosing loops.
//
void Compiler::optRecordLoopMemoryDependence(GenTree* tree, BasicBlock* block, ValueNum memoryVN)
{
    // Find the loop associated with this memory VN.
    //
    FlowGraphNaturalLoop* updateLoop = vnStore->LoopOfVN(memoryVN);

    if (updateLoop == nullptr)
    {
        // memoryVN defined outside of any loop, we can ignore.
        //
        JITDUMP("      ==> Not updating loop memory dependence of [%06u], memory " FMT_VN " not defined in a loop\n",
                dspTreeID(tree), memoryVN);
        return;
    }

    // If the memory definition is part of an ancestor loop then 'tree' depends
    // on memory defined in that ancestor loop. Otherwise we can also ignore
    // the update.
    //
    while ((updateLoop != nullptr) && !updateLoop->ContainsBlock(block))
    {
        updateLoop = updateLoop->GetParent();
    }

    if (updateLoop == nullptr)
    {
#ifdef DEBUG
        FlowGraphNaturalLoop* blockLoop = m_blockToLoop->GetLoop(block);

        JITDUMP("      ==> Not updating loop memory dependence of [%06u]/" FMT_LP ", memory definition " FMT_VN
                "/" FMT_LP " is not dependent on an ancestor loop\n",
                dspTreeID(tree), blockLoop->GetIndex(), memoryVN, vnStore->LoopOfVN(memoryVN)->GetIndex());
#endif
        return;
    }

    // If we already have a recorded a loop entry block for this
    // tree, see if the new update is for a more closely nested
    // loop.
    //
    NodeToLoopMemoryBlockMap* const map      = GetNodeToLoopMemoryBlockMap();
    BasicBlock*                     mapBlock = nullptr;

    if (map->Lookup(tree, &mapBlock))
    {
        // If the update loop contains the existing map block,
        // the existing entry is more constraining. So no
        // update needed.
        //
        if (updateLoop->ContainsBlock(mapBlock))
        {
#ifdef DEBUG
            FlowGraphNaturalLoop* mapLoop = m_blockToLoop->GetLoop(mapBlock);

            JITDUMP("      ==> Not updating loop memory dependence of [%06u]; already constrained to " FMT_LP
                    " nested in " FMT_LP "\n",
                    dspTreeID(tree), mapLoop->GetIndex(), updateLoop->GetIndex());
#endif
            return;
        }
    }

    // MemoryVN now describes the most constraining loop memory dependence
    // we know of. Update the map.
    //
    JITDUMP("      ==> Updating loop memory dependence of [%06u] to " FMT_LP "\n", dspTreeID(tree),
            updateLoop->GetIndex());
    map->Set(tree, updateLoop->GetHeader(), NodeToLoopMemoryBlockMap::Overwrite);
}

//------------------------------------------------------------------------
// optCopyLoopMemoryDependence: Recursively record that tree's loop memory dependence
//   is the same as some other tree.
//
// Arguments:
//   fromTree -- tree to copy dependence from
//   toTree -- tree in question
//
void Compiler::optCopyLoopMemoryDependence(GenTree* fromTree, GenTree* toTree)
{
    assert(fromTree->OperGet() == toTree->OperGet());

    NodeToLoopMemoryBlockMap* const map      = GetNodeToLoopMemoryBlockMap();
    BasicBlock*                     mapBlock = nullptr;

    if (map->Lookup(fromTree, &mapBlock))
    {
        map->Set(toTree, mapBlock);
    }

    GenTreeOperandIterator fromIterCur = fromTree->OperandsBegin();
    GenTreeOperandIterator fromIterEnd = fromTree->OperandsEnd();
    GenTreeOperandIterator toIterCur   = toTree->OperandsBegin();
    GenTreeOperandIterator toIterEnd   = toTree->OperandsEnd();

    while (fromIterCur != fromIterEnd)
    {
        optCopyLoopMemoryDependence(*fromIterCur, *toIterCur);
        ++fromIterCur;
        ++toIterCur;
    }

    assert(toIterCur == toIterEnd);
}

//------------------------------------------------------------------------
// AddVariableLiveness: Adds the variable liveness information for 'blk'
//
// Arguments:
//   comp - Compiler instance
//   blk  - Block whose liveness is to be added
//
void LoopSideEffects::AddVariableLiveness(Compiler* comp, BasicBlock* blk)
{
    VarSetOps::UnionD(comp, VarInOut, blk->bbLiveIn);
    VarSetOps::UnionD(comp, VarInOut, blk->bbLiveOut);

    VarSetOps::UnionD(comp, VarUseDef, blk->bbVarUse);
    VarSetOps::UnionD(comp, VarUseDef, blk->bbVarDef);
}

//------------------------------------------------------------------------
// AddModifiedField: Record that a field is modified in the loop.
//
// Arguments:
//   comp      - Compiler instance
//   fldHnd    - Field handle being modified
//   fieldKind - Kind of field
//
void LoopSideEffects::AddModifiedField(Compiler* comp, CORINFO_FIELD_HANDLE fldHnd, FieldKindForVN fieldKind)
{
    if (FieldsModified == nullptr)
    {
        FieldsModified = new (comp->getAllocatorLoopHoist()) FieldHandleSet(comp->getAllocatorLoopHoist());
    }
    FieldsModified->Set(fldHnd, fieldKind, FieldHandleSet::Overwrite);
}

//------------------------------------------------------------------------
// AddModifiedElemType: Record that an array with the specified element type is
// being modified.
//
// Arguments:
//   comp      - Compiler instance
//   structHnd - Handle for struct. Can also be an encoding of a primitive
//               handle, see {Encode/Decode}ElemType.
//
void LoopSideEffects::AddModifiedElemType(Compiler* comp, CORINFO_CLASS_HANDLE structHnd)
{
    if (ArrayElemTypesModified == nullptr)
    {
        ArrayElemTypesModified = new (comp->getAllocatorLoopHoist()) ClassHandleSet(comp->getAllocatorLoopHoist());
    }
    ArrayElemTypesModified->Set(structHnd, true, ClassHandleSet::Overwrite);
}

//------------------------------------------------------------------------
// optHoistLoopBlocks: Hoist invariant expression out of the loop.
//
// Arguments:
//    loop - The loop
//    traits - Bit vector traits for 'defExecuted'
//    defExecuted - Bit vector of definitely executed blocks in the loop
//    hoistContext - The loop hoist context
//
void Compiler::optHoistLoopBlocks(FlowGraphNaturalLoop* loop,
                                  BitVecTraits*         traits,
                                  BitVec                defExecuted,
                                  LoopHoistContext*     hoistContext)
{
    class HoistVisitor : public GenTreeVisitor<HoistVisitor>
    {
        class Value
        {
            GenTree* m_node;

        public:
            bool m_hoistable;
            bool m_cctorDependent;
            bool m_invariant;

#ifdef DEBUG
            const char* m_failReason;
#endif

            Value(GenTree* node)
                : m_node(node)
                , m_hoistable(false)
                , m_cctorDependent(false)
                , m_invariant(false)
            {
#ifdef DEBUG
                m_failReason = "unset";
#endif
            }

            GenTree* Node()
            {
                return m_node;
            }
        };

        ArrayStack<Value>     m_valueStack;
        bool                  m_beforeSideEffect;
        FlowGraphNaturalLoop* m_loop;
        LoopHoistContext*     m_hoistContext;
        BasicBlock*           m_currentBlock;
        BitVecTraits*         m_traits;
        BitVec                m_defExec;

        bool IsNodeHoistable(GenTree* node)
        {
            // TODO-CQ: This is a more restrictive version of a check that optIsCSEcandidate already does - it allows
            // a struct typed node if a class handle can be recovered from it.
            if (node->TypeIs(TYP_STRUCT))
            {
                return false;
            }
            else if (node->OperIs(GT_NULLCHECK))
            {
                // If a null-check is for `this` object, it is safe to
                // hoist it out of the loop. Assertionprop will get rid
                // of left over nullchecks present inside the loop. Also,
                // since NULLCHECK has no value, it will never be CSE,
                // hence this check is not present in optIsCSEcandidate().
                return true;
            }
            else if ((node->gtFlags & GTF_ORDER_SIDEEFF) != 0)
            {
                // If a node has an order side effect, we can't hoist it at all: we don't know what the order
                // dependence actually is. For example, assertion prop might have determined a node can't throw
                // an exception, and eliminated the GTF_EXCEPT flag, replacing it with GTF_ORDER_SIDEEFF. We
                // can't hoist because we might then hoist above the expression that led assertion prop to make
                // that decision. This can happen in JitOptRepeat, where hoisting can follow assertion prop.
                return false;
            }

            // Tree must be a suitable CSE candidate for us to be able to hoist it.
            return m_compiler->optIsCSEcandidate(node);
        }

        bool IsTreeVNInvariant(GenTree* tree)
        {
            ValueNum vn = tree->gtVNPair.GetLiberal();
            bool     vnIsInvariant =
                m_compiler->optVNIsLoopInvariant(vn, m_loop, &m_hoistContext->m_curLoopVnInvariantCache);

            // Even though VN is invariant in the loop (say a constant) its value may depend on position
            // of tree, so for loop hoisting we must also check that any memory read by tree
            // is also invariant in the loop.
            //
            if (vnIsInvariant)
            {
                vnIsInvariant = IsTreeLoopMemoryInvariant(tree);
            }
            return vnIsInvariant;
        }

        bool IsHoistableOverExcepSibling(GenTree* node, bool siblingHasExcep)
        {
            JITDUMP("      [%06u]", dspTreeID(node));

            if ((node->gtFlags & GTF_ALL_EFFECT) != 0)
            {
                // If the hoistable node has any side effects, make sure
                // we don't hoist it past a sibling that throws any exception.
                if (siblingHasExcep)
                {
                    JITDUMP(" not hoistable: cannot move past node that throws exception.\n");
                    return false;
                }
            }
            JITDUMP(" hoistable\n");
            return true;
        }

        //------------------------------------------------------------------------
        // IsTreeLoopMemoryInvariant: determine if the value number of tree
        //   is dependent on the tree being executed within the current loop
        //
        // Arguments:
        //   tree -- tree in question
        //
        // Returns:
        //   true if tree could be evaluated just before loop and get the
        //   same value.
        //
        // Note:
        //   Calls are optimistically assumed to be invariant.
        //   Caller must do their own analysis for these tree types.
        //
        bool IsTreeLoopMemoryInvariant(GenTree* tree)
        {
            if (tree->IsCall())
            {
                // Calls are handled specially by hoisting, and loop memory dependence
                // must be checked by other means.
                //
                return true;
            }

            NodeToLoopMemoryBlockMap* const map            = m_compiler->GetNodeToLoopMemoryBlockMap();
            BasicBlock*                     loopEntryBlock = nullptr;
            if (map->Lookup(tree, &loopEntryBlock))
            {
                for (MemoryKind memoryKind : allMemoryKinds())
                {
                    ValueNum loopMemoryVN =
                        m_compiler->GetMemoryPerSsaData(loopEntryBlock->bbMemorySsaNumIn[memoryKind])
                            ->m_vnPair.GetLiberal();
                    if (!m_compiler->optVNIsLoopInvariant(loopMemoryVN, m_loop,
                                                          &m_hoistContext->m_curLoopVnInvariantCache))
                    {
                        return false;
                    }
                }
            }

            return true;
        }

    public:
        enum
        {
            ComputeStack      = false,
            DoPreOrder        = true,
            DoPostOrder       = true,
            DoLclVarsOnly     = false,
            UseExecutionOrder = true,
        };

        HoistVisitor(Compiler*             compiler,
                     FlowGraphNaturalLoop* loop,
                     LoopHoistContext*     hoistContext,
                     BitVecTraits*         traits,
                     BitVec                defExec)
            : GenTreeVisitor(compiler)
            , m_valueStack(compiler->getAllocator(CMK_LoopHoist))
            , m_beforeSideEffect(true)
            , m_loop(loop)
            , m_hoistContext(hoistContext)
            , m_currentBlock(nullptr)
            , m_traits(traits)
            , m_defExec(defExec)
        {
        }

        void HoistBlock(BasicBlock* block)
        {
            m_currentBlock = block;
            for (Statement* const stmt : block->NonPhiStatements())
            {
                WalkTree(stmt->GetRootNodePointer(), nullptr);
                Value& top = m_valueStack.TopRef();
                assert(top.Node() == stmt->GetRootNode());

                // hoist the top node?
                if (top.m_hoistable)
                {
                    const bool defExecuted = BitVecOps::IsMember(m_traits, m_defExec, block->bbPostorderNum);
                    m_compiler->optHoistCandidate(stmt->GetRootNode(), block, m_loop, m_hoistContext, defExecuted);
                }
                else
                {
                    JITDUMP("      [%06u] %s: %s\n", dspTreeID(top.Node()),
                            top.m_invariant ? "not hoistable" : "not invariant", top.m_failReason);
                }

                m_valueStack.Reset();
            }

            // Only unconditionally executed blocks in the loop are visited (see optHoistThisLoop)
            // so after we're done visiting the first block we need to assume the worst, that the
            // blocks that are not visited have side effects.
            m_beforeSideEffect = false;
        }

        fgWalkResult PreOrderVisit(GenTree** use, GenTree* user)
        {
            GenTree* node = *use;
            JITDUMP("----- PreOrderVisit for [%06u] %s\n", dspTreeID(node), GenTree::OpName(node->OperGet()));
            m_valueStack.Emplace(node);
            return fgWalkResult::WALK_CONTINUE;
        }

        fgWalkResult PostOrderVisit(GenTree** use, GenTree* user)
        {
            GenTree* tree = *use;
            JITDUMP("----- PostOrderVisit for [%06u] %s\n", dspTreeID(tree), GenTree::OpName(tree->OperGet()));

            if (tree->OperIsLocalRead())
            {
                GenTreeLclVarCommon* lclVar = tree->AsLclVarCommon();
                unsigned             lclNum = lclVar->GetLclNum();

                // To be invariant the variable must be in SSA ...
                bool isInvariant = lclVar->HasSsaName();
                // and the SSA definition must be outside the loop we're hoisting from ...
                isInvariant =
                    isInvariant && !m_loop->ContainsBlock(
                                       m_compiler->lvaGetDesc(lclNum)->GetPerSsaData(lclVar->GetSsaNum())->GetBlock());

                // and the VN of the tree is considered invariant as well.
                //
                // TODO-CQ: This VN invariance check should not be necessary and in some cases it is conservative - it
                // is possible that the SSA def is outside the loop but VN does not understand what the node is doing
                // (e.g. LCL_FLD-based type reinterpretation) and assigns a "new, unique VN" to the node. This VN is
                // associated with the block where the node is, a loop block, and thus the VN is considered to not be
                // invariant.
                // On the other hand, it is possible for a SSA def to be inside the loop yet the use to be invariant,
                // if the defining expression is also invariant. In such a case the VN invariance would help but it is
                // blocked by the SSA invariance check.
                isInvariant = isInvariant && IsTreeVNInvariant(tree);

                Value& top = m_valueStack.TopRef();
                assert(top.Node() == tree);

                if (isInvariant)
                {
                    top.m_invariant = true;
                    // In general it doesn't make sense to hoist a local node but there are exceptions, for example
                    // LCL_FLD nodes (because then the variable cannot be enregistered and the node always turns
                    // into a memory access).
                    top.m_hoistable = IsNodeHoistable(tree);
                }

#ifdef DEBUG
                if (!isInvariant)
                {
                    top.m_failReason = "local, not rvalue / not in SSA / defined within current loop";
                }
                else if (!top.m_hoistable)
                {
                    top.m_failReason = "not handled by hoisting or CSE";
                }
#endif

                JITDUMP("      [%06u] %s: %s: %s\n", dspTreeID(tree), GenTree::OpName(tree->OperGet()),
                        top.m_invariant ? (top.m_hoistable ? "hoistable" : "not hoistable") : "not invariant",
                        top.m_failReason);

                return fgWalkResult::WALK_CONTINUE;
            }

            bool treeIsCctorDependent     = tree->OperIsIndir() && ((tree->gtFlags & GTF_IND_INITCLASS) != 0);
            bool treeIsInvariant          = true;
            bool treeHasHoistableChildren = false;
            int  childCount;

#ifdef DEBUG
            const char* failReason = "unknown";
#endif

            for (childCount = 0; m_valueStack.TopRef(childCount).Node() != tree; childCount++)
            {
                Value& child = m_valueStack.TopRef(childCount);

                if (child.m_hoistable)
                {
                    treeHasHoistableChildren = true;
                }

                if (!child.m_invariant)
                {
                    treeIsInvariant = false;
                    INDEBUG(failReason = "variant child";)
                }

                if (child.m_cctorDependent)
                {
                    // Normally, a parent of a cctor-dependent tree is also cctor-dependent.
                    treeIsCctorDependent = true;

                    // Check for the case where we can stop propagating cctor-dependent upwards.
                    if (tree->OperIs(GT_COMMA) && (child.Node() == tree->gtGetOp2()))
                    {
                        GenTree* op1 = tree->gtGetOp1();
                        if (op1->OperIs(GT_CALL))
                        {
                            GenTreeCall* call = op1->AsCall();
                            if (call->IsHelperCall() &&
                                s_helperCallProperties.MayRunCctor(eeGetHelperNum(call->gtCallMethHnd)))
                            {
                                // Hoisting the comma is ok because it would hoist the initialization along
                                // with the static field reference.
                                treeIsCctorDependent = false;
                                // Hoisting the static field without hoisting the initialization would be
                                // incorrect, make sure we consider the field (which we flagged as
                                // cctor-dependent) non-hoistable.
                                noway_assert(!child.m_hoistable);
                            }
                        }
                    }
                }
            }

            // If all the children of "tree" are hoistable, then "tree" itself can be hoisted,
            // unless it has a static var reference that can't be hoisted past its cctor call.
            bool treeIsHoistable = treeIsInvariant && !treeIsCctorDependent;

#ifdef DEBUG
            if (treeIsInvariant && !treeIsHoistable)
            {
                failReason = "cctor dependent";
            }
#endif

            // But we must see if anything else prevents "tree" from being hoisted.
            //
            if (treeIsInvariant)
            {
                if (treeIsHoistable)
                {
                    treeIsHoistable = IsNodeHoistable(tree);
                    if (!treeIsHoistable)
                    {
                        INDEBUG(failReason = "not handled by hoisting or CSE";)
                    }
                }

                // If it's a call, it must be a helper call, and be pure.
                // Further, if it may run a cctor, it must be labeled as "Hoistable"
                // (meaning it won't run a cctor because the class is not precise-init).
                if (treeIsHoistable && tree->IsCall())
                {
                    GenTreeCall* call = tree->AsCall();
                    if (!call->IsHelperCall())
                    {
                        INDEBUG(failReason = "non-helper call";)
                        treeIsHoistable = false;
                    }
                    else
                    {
                        CorInfoHelpFunc helpFunc = eeGetHelperNum(call->gtCallMethHnd);
                        if (!s_helperCallProperties.IsPure(helpFunc))
                        {
                            INDEBUG(failReason = "impure helper call";)
                            treeIsHoistable = false;
                        }
                        else if (s_helperCallProperties.MayRunCctor(helpFunc) &&
                                 ((call->gtFlags & GTF_CALL_HOISTABLE) == 0))
                        {
                            INDEBUG(failReason = "non-hoistable helper call";)
                            treeIsHoistable = false;
                        }
                    }
                }

                if (treeIsHoistable)
                {
                    if (!m_beforeSideEffect)
                    {
                        // For now, we give up on an expression that might raise an exception if it is after the
                        // first possible global side effect (and we assume we're after that if we're not in the first
                        // block).
                        // TODO-CQ: this is when we might do loop cloning.
                        //
                        if ((tree->gtFlags & GTF_EXCEPT) != 0)
                        {
                            INDEBUG(failReason = "side effect ordering constraint";)
                            treeIsHoistable = false;
                        }
                    }
                }

                // Is the value of the whole tree loop invariant?
                treeIsInvariant = IsTreeVNInvariant(tree);

                // Is the value of the whole tree loop invariant?
                if (!treeIsInvariant)
                {
                    // Here we have a tree that is not loop invariant and we thus cannot hoist
                    INDEBUG(failReason = "tree VN is loop variant";)
                    treeIsHoistable = false;
                }
            }

            // Next check if we need to set 'm_beforeSideEffect' to false.
            //
            // If we have already set it to false then we can skip these checks
            //
            if (m_beforeSideEffect)
            {
                // Is the value of the whole tree loop invariant?
                if (!treeIsInvariant)
                {
                    // We have a tree that is not loop invariant and we thus cannot hoist
                    assert(treeIsHoistable == false);

                    // Check if we should clear m_beforeSideEffect.
                    // If 'tree' can throw an exception then we need to set m_beforeSideEffect to false.
                    // Note that calls are handled below
                    if (tree->OperMayThrow(m_compiler) && !tree->IsCall())
                    {
                        m_beforeSideEffect = false;
                    }
                }

                // In the section below, we only care about memory side effects.  We assume that expressions will
                // be hoisted so that they are evaluated in the same order as they would have been in the loop,
                // and therefore throw exceptions in the same order.
                //
                if (tree->IsCall())
                {
                    // If it's a call, it must be a helper call that does not mutate the heap.
                    // Further, if it may run a cctor, it must be labeled as "Hoistable"
                    // (meaning it won't run a cctor because the class is not precise-init).
                    GenTreeCall* call = tree->AsCall();
                    if (!call->IsHelperCall())
                    {
                        m_beforeSideEffect = false;
                    }
                    else
                    {
                        CorInfoHelpFunc helpFunc = eeGetHelperNum(call->gtCallMethHnd);
                        if (s_helperCallProperties.MutatesHeap(helpFunc))
                        {
                            m_beforeSideEffect = false;
                        }
                        else if (s_helperCallProperties.MayRunCctor(helpFunc) &&
                                 (call->gtFlags & GTF_CALL_HOISTABLE) == 0)
                        {
                            m_beforeSideEffect = false;
                        }

                        // Additional check for helper calls that throw exceptions
                        if (!treeIsInvariant)
                        {
                            // We have a tree that is not loop invariant and we thus cannot hoist
                            assert(treeIsHoistable == false);

                            // Does this helper call throw?
                            if (!s_helperCallProperties.NoThrow(helpFunc))
                            {
                                m_beforeSideEffect = false;
                            }
                        }
                    }
                }
                else if (tree->OperRequiresAsgFlag())
                {
                    // Assume all stores except "STORE_LCL_VAR<non-addr-exposed lcl>(...)" are globally visible.
                    bool isGloballyVisibleStore;
                    if (tree->OperIsLocalStore())
                    {
                        isGloballyVisibleStore = m_compiler->lvaGetDesc(tree->AsLclVarCommon())->IsAddressExposed();
                    }
                    else
                    {
                        isGloballyVisibleStore = true;
                    }

                    if (isGloballyVisibleStore)
                    {
                        INDEBUG(failReason = "store to globally visible memory");
                        treeIsHoistable    = false;
                        m_beforeSideEffect = false;
                    }
                }
            }

            // If this 'tree' is hoistable then we return and the caller will
            // decide to hoist it as part of larger hoistable expression.
            //
            if (!treeIsHoistable && treeHasHoistableChildren)
            {
                // The current tree is not hoistable but it has hoistable children that we need
                // to hoist now.
                //
                // In order to preserve the original execution order, we also need to hoist any
                // other hoistable trees that we encountered so far.
                // At this point the stack contains (in top to bottom order):
                //   - the current node's children
                //   - the current node
                //   - ancestors of the current node and some of their descendants
                //
                // The ancestors have not been visited yet in post order so they're not hoistable
                // (and they cannot become hoistable because the current node is not) but some of
                // their descendants may have already been traversed and be hoistable.
                //
                // The execution order is actually bottom to top so we'll start hoisting from
                // the bottom of the stack, skipping the current node (which is expected to not
                // be hoistable).
                //
                // Note that the treeHasHoistableChildren check avoids unnecessary stack traversing
                // and also prevents hoisting trees too early. If the current tree is not hoistable
                // and it doesn't have any hoistable children then there's no point in hoisting any
                // other trees. Doing so would interfere with the cctor dependent case, where the
                // cctor dependent node is initially not hoistable and may become hoistable later,
                // when its parent comma node is visited.
                //
                // TODO-CQ: Ideally, we should be hoisting all the nodes having side-effects in execution
                // order as well as the ones that don't have side-effects at all. However, currently, we
                // just restrict hoisting a node(s) (that are children of `comma`) if one of the siblings
                // (which is executed before the given node) has side-effects (exceptions). Descendants
                // of ancestors might have side-effects and we might hoist nodes past them. This needs
                // to be addressed properly.
                bool visitedCurr = false;
                bool isCommaTree = tree->OperIs(GT_COMMA);
                bool hasExcep    = false;
                for (int i = 0; i < m_valueStack.Height(); i++)
                {
                    Value& value = m_valueStack.BottomRef(i);

                    if (value.m_hoistable)
                    {
                        assert(value.Node() != tree);

                        if (IsHoistableOverExcepSibling(value.Node(), hasExcep))
                        {
                            const bool defExecuted =
                                BitVecOps::IsMember(m_traits, m_defExec, m_currentBlock->bbPostorderNum);
                            m_compiler->optHoistCandidate(value.Node(), m_currentBlock, m_loop, m_hoistContext,
                                                          defExecuted);
                        }

                        // Don't hoist this tree again.
                        value.m_hoistable = false;
                        value.m_invariant = false;
                    }
                    else if (value.Node() != tree)
                    {
                        if (visitedCurr && isCommaTree)
                        {
                            // If we have visited current tree, now we are visiting children.
                            // For GT_COMMA nodes, we want to track if any children throws and
                            // should not hoist further children past it.
                            hasExcep = (tree->gtFlags & GTF_EXCEPT) != 0;
                        }
                        JITDUMP("      [%06u] %s: %s\n", dspTreeID(value.Node()),
                                value.m_invariant ? "not hoistable" : "not invariant", value.m_failReason);
                    }
                    else
                    {
                        visitedCurr = true;
                        JITDUMP("      [%06u] not hoistable : current node\n", dspTreeID(value.Node()));
                    }
                }
            }

            m_valueStack.Pop(childCount);

            Value& top = m_valueStack.TopRef();
            assert(top.Node() == tree);
            top.m_hoistable      = treeIsHoistable;
            top.m_cctorDependent = treeIsCctorDependent;
            top.m_invariant      = treeIsInvariant;

#ifdef DEBUG
            if (!top.m_invariant || !top.m_hoistable)
            {
                top.m_failReason = failReason;
            }
#endif

            return fgWalkResult::WALK_CONTINUE;
        }
    };

    HoistVisitor visitor(this, loop, hoistContext, traits, defExecuted);
    loop->VisitLoopBlocks([&](BasicBlock* block) -> BasicBlockVisit {
        const weight_t blockWeight = block->getBBWeight(this);

        JITDUMP("\n    optHoistLoopBlocks " FMT_BB " (weight=%6s) of loop " FMT_LP " (head: " FMT_BB ")\n",
                block->bbNum, refCntWtd2str(blockWeight, /* padForDecimalPlaces */ true), loop->GetIndex(),
                loop->GetHeader()->bbNum);

        if (blockWeight < (BB_UNITY_WEIGHT / 10))
        {
            JITDUMP("      block weight is too small to perform hoisting.\n");
        }
        else
        {
            visitor.HoistBlock(block);
        }

        return BasicBlockVisit::Continue;
    });

    hoistContext->ResetHoistedInCurLoop();
}

void Compiler::optHoistCandidate(
    GenTree* tree, BasicBlock* treeBb, FlowGraphNaturalLoop* loop, LoopHoistContext* hoistCtxt, bool defExecuted)
{
    // It must pass the hoistable profitability tests for this loop level
    if (!optIsProfitableToHoistTree(tree, loop, hoistCtxt, defExecuted))
    {
        JITDUMP("   ... not profitable to hoist\n");
        return;
    }

    if (hoistCtxt->GetHoistedInCurLoop(this)->Lookup(tree->gtVNPair.GetLiberal()))
    {
        // already hoisted this expression in the current loop, so don't hoist this expression.

        JITDUMP("      [%06u] ... already hoisted " FMT_VN " in " FMT_LP "\n ", dspTreeID(tree),
                tree->gtVNPair.GetLiberal(), loop->GetIndex());
        return;
    }

    // We should already have a pre-header for the loop.
    assert(loop->EntryEdges().size() == 1);
    BasicBlock* preheader = loop->EntryEdge(0)->getSourceBlock();

    // If the block we're hoisting from and the pre-header are in different EH regions, don't hoist.
    // TODO: we could probably hoist things that won't raise exceptions, such as constants.
    if (!BasicBlock::sameTryRegion(preheader, treeBb))
    {
        JITDUMP("   ... not hoisting in " FMT_LP ", eh region constraint (pre-header try index %d, candidate " FMT_BB
                " try index %d\n",
                loop->GetIndex(), preheader->bbTryIndex, treeBb->bbNum, treeBb->bbTryIndex);
        return;
    }

#if defined(DEBUG)

    // Punt if we've reached the hoisting limit.
    int      limit   = JitConfig.JitHoistLimit();
    unsigned current = m_totalHoistedExpressions; // this doesn't include the current candidate yet

    if ((limit >= 0) && (current >= static_cast<unsigned>(limit)))
    {
        JITDUMP("   ... not hoisting in " FMT_LP ", hoist count %u >= JitHoistLimit %u\n", loop->GetIndex(), current,
                static_cast<unsigned>(limit));
        return;
    }

#endif // defined(DEBUG)

    // Expression can be hoisted
    optPerformHoistExpr(tree, treeBb, loop);

    // Increment lpHoistedExprCount or lpHoistedFPExprCount
    if (varTypeUsesIntReg(tree))
    {
        hoistCtxt->m_hoistedExprCount++;
#ifndef TARGET_64BIT
        // For our 32-bit targets Long types take two registers.
        if (varTypeIsLong(tree->TypeGet()))
        {
            hoistCtxt->m_hoistedExprCount++;
        }
#endif
    }
#ifdef FEATURE_MASKED_HW_INTRINSICS
    else if (varTypeUsesMaskReg(tree))
    {
        hoistCtxt->m_hoistedMskExprCount++;
    }
#endif // FEATURE_MASKED_HW_INTRINSICS
    else
    {
        assert(varTypeUsesFloatReg(tree));
        hoistCtxt->m_hoistedFPExprCount++;
    }

    // Record the hoisted expression in hoistCtxt
    hoistCtxt->GetHoistedInCurLoop(this)->Set(tree->gtVNPair.GetLiberal(), true);

    Metrics.HoistedExpressions++;
}

bool Compiler::optVNIsLoopInvariant(ValueNum vn, FlowGraphNaturalLoop* loop, VNSet* loopVnInvariantCache)
{
    // If it is not a VN, is not loop-invariant.
    if (vn == ValueNumStore::NoVN)
    {
        return false;
    }

    // We'll always short-circuit constants.
    if (vnStore->IsVNConstant(vn) || vn == vnStore->VNForVoid())
    {
        return true;
    }

    // If we've done this query previously, don't repeat.
    bool previousRes = false;
    if (loopVnInvariantCache->Lookup(vn, &previousRes))
    {
        return previousRes;
    }

    bool           res = true;
    VNFuncApp      funcApp;
    VNPhiDef       phiDef;
    VNMemoryPhiDef memoryPhiDef;
    if (vnStore->GetVNFunc(vn, &funcApp))
    {
        if (funcApp.m_func == VNF_MemOpaque)
        {
            const unsigned loopIndex = funcApp.m_args[0];

            // Check for the special "ambiguous" loop index.
            // This is considered variant in every loop.
            //
            if (loopIndex == ValueNumStore::UnknownLoop)
            {
                res = false;
            }
            else if (loopIndex == ValueNumStore::NoLoop)
            {
                res = true;
            }
            else
            {
                FlowGraphNaturalLoop* otherLoop = m_loops->GetLoopByIndex(loopIndex);
                assert(otherLoop != nullptr);
                res = !loop->ContainsLoop(otherLoop);
            }
        }
        else
        {
            for (unsigned i = 0; i < funcApp.m_arity; i++)
            {
                // 4th arg of mapStore identifies the loop where the store happens.
                //
                if (funcApp.m_func == VNF_MapStore)
                {
                    assert(funcApp.m_arity == 4);

                    if (i == 3)
                    {
                        const unsigned loopIndex = funcApp.m_args[3];
                        assert((loopIndex == ValueNumStore::NoLoop) || (loopIndex < m_loops->NumLoops()));
                        if (loopIndex == ValueNumStore::NoLoop)
                        {
                            res = true;
                        }
                        else
                        {
                            FlowGraphNaturalLoop* otherLoop = m_loops->GetLoopByIndex(loopIndex);
                            res                             = !loop->ContainsLoop(otherLoop);
                        }
                        break;
                    }
                }

                // TODO-CQ: We need to either make sure that *all* VN functions
                // always take VN args, or else have a list of arg positions to exempt, as implicitly
                // constant.
                if (!optVNIsLoopInvariant(funcApp.m_args[i], loop, loopVnInvariantCache))
                {
                    res = false;
                    break;
                }
            }
        }
    }
    else if (vnStore->GetPhiDef(vn, &phiDef))
    {
        // Is the definition within the loop?  If so, is not loop-invariant.
        LclSsaVarDsc* ssaDef = lvaTable[phiDef.LclNum].GetPerSsaData(phiDef.SsaDef);
        res                  = !loop->ContainsBlock(ssaDef->GetBlock());
    }
    else if (vnStore->GetMemoryPhiDef(vn, &memoryPhiDef))
    {
        res = !loop->ContainsBlock(memoryPhiDef.Block);
    }

    loopVnInvariantCache->Set(vn, res);
    return res;
}

//------------------------------------------------------------------------------
// fgSetEHRegionForNewPreheaderOrExit: Set the EH region for a newly inserted
// preheader or exit block.
//
// In which EH region should the block live?
//
// If the `next` block is NOT the first block of a `try` region, the new block
// can simply extend the next block's EH region.
//
// If the `next` block IS the first block of a `try`, we find its parent region
// and use that. For mutual-protect regions, we need to find the actual parent,
// as the block stores the most "nested" mutual region. For non-mutual-protect
// regions, due to EH canonicalization, we are guaranteed that no other EH
// regions begin on the same block, so looking to just the parent is
// sufficient.
// Note that we can't just extend the EH region of the next block to the new
// block, because it may still be the target of other branches. If those
// branches come from outside the `try` then we can't branch to a non-first
// `try` region block (you always must enter the `try` in the first block). For
// example, for the preheader we can have backedges that come from outside the
// `try` (if, say, only the top half of the loop is a `try` region). For exits,
// we could similarly have branches to the old exit block from outside the `try`.
//
// Note that hoisting any code out of a try region, for example, to a preheader
// block in a different EH region, needs to ensure that no exceptions will be
// thrown. Similar considerations are required for exits.
//
// Arguments:
//    block - the new block, which has already been added to the
//            block list.
//
void Compiler::fgSetEHRegionForNewPreheaderOrExit(BasicBlock* block)
{
    BasicBlock* next = block->Next();

    if (bbIsTryBeg(next))
    {
        // `next` is the beginning of a try block. Figure out the EH region to use.
        assert(next->hasTryIndex());
        unsigned newTryIndex = ehTrueEnclosingTryIndex(next->getTryIndex());
        if (newTryIndex == EHblkDsc::NO_ENCLOSING_INDEX)
        {
            // No EH try index.
            block->clearTryIndex();
        }
        else
        {
            block->setTryIndex(newTryIndex);
        }

        // What handler region to use? Use the same handler region as `next`.
        block->copyHndIndex(next);
    }
    else
    {
        fgExtendEHRegionBefore(next);
    }
}

LoopSideEffects::LoopSideEffects()
    : VarInOut(VarSetOps::UninitVal())
    , VarUseDef(VarSetOps::UninitVal())
{
    for (MemoryKind mk : allMemoryKinds())
    {
        HasMemoryHavoc[mk] = false;
    }
}

void Compiler::optComputeLoopSideEffects()
{
    m_loopSideEffects =
        m_loops->NumLoops() == 0 ? nullptr : (new (this, CMK_LoopOpt) LoopSideEffects[m_loops->NumLoops()]);

    for (FlowGraphNaturalLoop* loop : m_loops->InReversePostOrder())
    {
        m_loopSideEffects[loop->GetIndex()].VarInOut  = VarSetOps::MakeEmpty(this);
        m_loopSideEffects[loop->GetIndex()].VarUseDef = VarSetOps::MakeEmpty(this);
    }

    BasicBlock** postOrder      = m_dfsTree->GetPostOrder();
    unsigned     postOrderCount = m_dfsTree->GetPostOrderCount();

    // Iterate all blocks in loops.
    for (FlowGraphNaturalLoop* loop : m_loops->InReversePostOrder())
    {
        if (loop->GetParent() != nullptr)
        {
            continue;
        }

        // The side effect code benefits from seeing things in RPO as it has some
        // limited treatment assignments it has seen the value of.
        loop->VisitLoopBlocksReversePostOrder([=](BasicBlock* loopBlock) {
            FlowGraphNaturalLoop* loop = m_blockToLoop->GetLoop(loopBlock);
            assert(loop != nullptr);
            optComputeLoopSideEffectsOfBlock(loopBlock, loop);

            return BasicBlockVisit::Continue;
        });
    }
}

void Compiler::optComputeInterestingVarSets()
{
    VarSetOps::AssignNoCopy(this, lvaFloatVars, VarSetOps::MakeEmpty(this));
#ifndef TARGET_64BIT
    VarSetOps::AssignNoCopy(this, lvaLongVars, VarSetOps::MakeEmpty(this));
#endif
#ifdef FEATURE_MASKED_HW_INTRINSICS
    VarSetOps::AssignNoCopy(this, lvaMaskVars, VarSetOps::MakeEmpty(this));
#endif

    for (unsigned i = 0; i < lvaCount; i++)
    {
        LclVarDsc* varDsc = lvaGetDesc(i);
        if (varDsc->lvTracked)
        {
            if (varTypeUsesFloatReg(varDsc->lvType))
            {
                VarSetOps::AddElemD(this, lvaFloatVars, varDsc->lvVarIndex);
            }
#ifndef TARGET_64BIT
            else if (varTypeIsLong(varDsc->lvType))
            {
                VarSetOps::AddElemD(this, lvaLongVars, varDsc->lvVarIndex);
            }
#endif
#ifdef FEATURE_MASKED_HW_INTRINSICS
            else if (varTypeUsesMaskReg(varDsc->lvType))
            {
                VarSetOps::AddElemD(this, lvaMaskVars, varDsc->lvVarIndex);
            }
#endif // FEATURE_MASKED_HW_INTRINSICS
        }
    }
}

void Compiler::optRecordLoopNestsMemoryHavoc(FlowGraphNaturalLoop* loop, MemoryKindSet memoryHavoc)
{
    do
    {
        for (MemoryKind memoryKind : allMemoryKinds())
        {
            if ((memoryHavoc & memoryKindSet(memoryKind)) != 0)
            {
                m_loopSideEffects[loop->GetIndex()].HasMemoryHavoc[memoryKind] = true;
            }
        }

        loop = loop->GetParent();
    } while (loop != nullptr);
}

void Compiler::optComputeLoopSideEffectsOfBlock(BasicBlock* blk, FlowGraphNaturalLoop* mostNestedLoop)
{
    JITDUMP("optComputeLoopSideEffectsOfBlock " FMT_BB ", mostNestedLoop " FMT_LP "\n", blk->bbNum,
            mostNestedLoop->GetIndex());
    AddVariableLivenessAllContainingLoops(mostNestedLoop, blk);

    // MemoryKinds for which an in-loop call or store has arbitrary effects.
    MemoryKindSet memoryHavoc = emptyMemoryKindSet;

    // Now iterate over the remaining statements, and their trees.
    for (Statement* const stmt : blk->NonPhiStatements())
    {
        for (GenTree* const tree : stmt->TreeList())
        {
            genTreeOps oper = tree->OperGet();

            // Even after we set memoryHavoc we still may want to know if a loop contains calls
            if (memoryHavoc == fullMemoryKindSet)
            {
                if (oper == GT_CALL)
                {
                    // Record that this loop contains a call
                    AddContainsCallAllContainingLoops(mostNestedLoop);
                }

                // If we just marked it as containing a call or it was previously set
                if (m_loopSideEffects[mostNestedLoop->GetIndex()].ContainsCall)
                {
                    // We can early exit after both memoryHavoc and ContainsCall are both set to true.
                    break;
                }

                // We are just looking for GT_CALL nodes after memoryHavoc was set.
                continue;
            }

            // otherwise memoryHavoc is not set for at least one heap ID
            assert(memoryHavoc != fullMemoryKindSet);

            // This body is a distillation of the memory side-effect code of value numbering.
            // We also do a very limited analysis if byref PtrTo values, to cover some cases
            // that the compiler creates.
            switch (oper)
            {
                case GT_STORE_LCL_VAR:
                case GT_STORE_LCL_FLD:
                {
                    GenTreeLclVarCommon* lcl    = tree->AsLclVarCommon();
                    ValueNum             dataVN = lcl->Data()->gtVNPair.GetLiberal();

                    // If we gave the data a value number, propagate it.
                    if (lcl->OperIs(GT_STORE_LCL_VAR) && (dataVN != ValueNumStore::NoVN))
                    {
                        dataVN = vnStore->VNNormalValue(dataVN);
                        if (lcl->HasSsaName())
                        {
                            lvaTable[lcl->GetLclNum()].GetPerSsaData(lcl->GetSsaNum())->m_vnPair.SetLiberal(dataVN);
                        }
                    }

                    // If the local is address-exposed, count this as ByrefExposed havoc
                    if (lvaVarAddrExposed(lcl->GetLclNum()))
                    {
                        memoryHavoc |= memoryKindSet(ByrefExposed);
                    }
                }
                break;

                case GT_STOREIND:
                case GT_STORE_BLK:
                {
                    if (tree->AsIndir()->IsVolatile())
                    {
                        memoryHavoc |= memoryKindSet(GcHeap, ByrefExposed);
                        continue;
                    }

                    GenTree* addr = tree->AsIndir()->Addr()->gtEffectiveVal();

                    if (addr->TypeIs(TYP_BYREF) && addr->OperIs(GT_LCL_VAR))
                    {
                        // If it's a local byref for which we recorded a value number, use that...
                        GenTreeLclVar* argLcl = addr->AsLclVar();
                        if (argLcl->HasSsaName())
                        {
                            ValueNum argVN =
                                lvaTable[argLcl->GetLclNum()].GetPerSsaData(argLcl->GetSsaNum())->m_vnPair.GetLiberal();
                            VNFuncApp funcApp;
                            if (argVN != ValueNumStore::NoVN && vnStore->GetVNFunc(argVN, &funcApp) &&
                                funcApp.m_func == VNF_PtrToArrElem)
                            {
                                assert(vnStore->IsVNHandle(funcApp.m_args[0]));
                                CORINFO_CLASS_HANDLE elemType =
                                    CORINFO_CLASS_HANDLE(vnStore->ConstantValue<size_t>(funcApp.m_args[0]));
                                AddModifiedElemTypeAllContainingLoops(mostNestedLoop, elemType);
                                // Don't set memoryHavoc for GcHeap below.  Do set memoryHavoc for ByrefExposed
                                // (conservatively assuming that a byref may alias the array element)
                                memoryHavoc |= memoryKindSet(ByrefExposed);
                                continue;
                            }
                        }
                        // Otherwise...
                        memoryHavoc |= memoryKindSet(GcHeap, ByrefExposed);
                    }
                    else
                    {
                        GenTreeArrAddr* arrAddr  = nullptr;
                        GenTree*        baseAddr = nullptr;
                        FieldSeq*       fldSeq   = nullptr;
                        ssize_t         offset   = 0;

                        if (addr->IsArrayAddr(&arrAddr))
                        {
                            // We will not collect "fldSeq" -- any modification to an S[], at
                            // any field of "S", will lose all information about the array type.
                            CORINFO_CLASS_HANDLE elemTypeEq =
                                EncodeElemType(arrAddr->GetElemType(), arrAddr->GetElemClassHandle());
                            AddModifiedElemTypeAllContainingLoops(mostNestedLoop, elemTypeEq);
                            // Conservatively assume byrefs may alias this array element
                            memoryHavoc |= memoryKindSet(ByrefExposed);
                        }
                        else if (addr->IsFieldAddr(this, &baseAddr, &fldSeq, &offset))
                        {
                            assert(fldSeq != nullptr);

                            FieldKindForVN fieldKind =
                                (baseAddr != nullptr) ? FieldKindForVN::WithBaseAddr : FieldKindForVN::SimpleStatic;
                            AddModifiedFieldAllContainingLoops(mostNestedLoop, fldSeq->GetFieldHandle(), fieldKind);
                            // Conservatively assume byrefs may alias this object.
                            memoryHavoc |= memoryKindSet(ByrefExposed);
                        }
                        else
                        {
                            memoryHavoc |= memoryKindSet(GcHeap, ByrefExposed);
                        }
                    }
                }
                break;

                case GT_COMMA:
                    tree->gtVNPair = tree->AsOp()->gtOp2->gtVNPair;
                    break;

                // Is it an addr of an array index expression?
                case GT_ARR_ADDR:
                {
                    CORINFO_CLASS_HANDLE elemTypeEq =
                        EncodeElemType(tree->AsArrAddr()->GetElemType(), tree->AsArrAddr()->GetElemClassHandle());
                    ValueNum elemTypeEqVN = vnStore->VNForHandle(ssize_t(elemTypeEq), GTF_ICON_CLASS_HDL);

                    // Label this with a "dummy" PtrToArrElem so that we pick it up when looking at the ASG.
                    ValueNum ptrToArrElemVN =
                        vnStore->VNForFunc(TYP_BYREF, VNF_PtrToArrElem, elemTypeEqVN, vnStore->VNForNull(),
                                           vnStore->VNForNull(), vnStore->VNForNull());
                    tree->gtVNPair.SetBoth(ptrToArrElemVN);
                }
                break;

#ifdef FEATURE_HW_INTRINSICS
                case GT_HWINTRINSIC:
                {
                    GenTreeHWIntrinsic* hwintrinsic = tree->AsHWIntrinsic();
                    NamedIntrinsic      intrinsicId = hwintrinsic->GetHWIntrinsicId();

                    if (hwintrinsic->OperIsMemoryStoreOrBarrier())
                    {
                        // For barriers, we model the behavior after GT_MEMORYBARRIER
                        memoryHavoc |= memoryKindSet(GcHeap, ByrefExposed);
                    }
                    break;
                }
#endif // FEATURE_HW_INTRINSICS

                case GT_LOCKADD:
                case GT_XORR:
                case GT_XAND:
                case GT_XADD:
                case GT_XCHG:
                case GT_CMPXCHG:
                case GT_MEMORYBARRIER:
                {
                    memoryHavoc |= memoryKindSet(GcHeap, ByrefExposed);
                }
                break;

                case GT_CALL:
                {
                    GenTreeCall* call = tree->AsCall();

                    // Record that this loop contains a call
                    AddContainsCallAllContainingLoops(mostNestedLoop);

                    if (call->IsHelperCall())
                    {
                        CorInfoHelpFunc helpFunc = eeGetHelperNum(call->gtCallMethHnd);
                        if (s_helperCallProperties.MutatesHeap(helpFunc))
                        {
                            memoryHavoc |= memoryKindSet(GcHeap, ByrefExposed);
                        }
                        else if (s_helperCallProperties.MayRunCctor(helpFunc))
                        {
                            // If the call is labeled as "Hoistable", then we've checked the
                            // class that would be constructed, and it is not precise-init, so
                            // the cctor will not be run by this call.  Otherwise, it might be,
                            // and might have arbitrary side effects.
                            if ((tree->gtFlags & GTF_CALL_HOISTABLE) == 0)
                            {
                                memoryHavoc |= memoryKindSet(GcHeap, ByrefExposed);
                            }
                        }
                    }
                    else
                    {
                        memoryHavoc |= memoryKindSet(GcHeap, ByrefExposed);
                    }
                    break;
                }

                default:
                    // All other gtOper node kinds, leave 'memoryHavoc' unchanged (i.e. false)
                    assert(!tree->OperRequiresAsgFlag());
                    break;
            }
        }

        // Clear the Value Number from the statement root node, if it was set above. This is to
        // ensure that for those blocks that are unreachable, which we still handle in this loop
        // but not during Value Numbering, fgDebugCheckExceptionSets() will skip the trees. Ideally,
        // we wouldn't be touching the gtVNPair at all (here) before actual Value Numbering.
        stmt->GetRootNode()->gtVNPair.SetBoth(ValueNumStore::NoVN);
    }

    if (memoryHavoc != emptyMemoryKindSet)
    {
        // Record that all loops containing this block have this kind of memoryHavoc effects.
        optRecordLoopNestsMemoryHavoc(mostNestedLoop, memoryHavoc);
    }
}

// Marks the containsCall information to "loop" and any parent loops.
void Compiler::AddContainsCallAllContainingLoops(FlowGraphNaturalLoop* loop)
{
    do
    {
        m_loopSideEffects[loop->GetIndex()].ContainsCall = true;
        loop                                             = loop->GetParent();
    } while (loop != nullptr);
}

// Adds the variable liveness information for 'blk' to "lnum" and any parent loops.
void Compiler::AddVariableLivenessAllContainingLoops(FlowGraphNaturalLoop* loop, BasicBlock* blk)
{
    do
    {
        m_loopSideEffects[loop->GetIndex()].AddVariableLiveness(this, blk);
        loop = loop->GetParent();
    } while (loop != nullptr);
}

// Adds "fldHnd" to the set of modified fields of "loop" and any parent loops.
void Compiler::AddModifiedFieldAllContainingLoops(FlowGraphNaturalLoop* loop,
                                                  CORINFO_FIELD_HANDLE  fldHnd,
                                                  FieldKindForVN        fieldKind)
{
    do
    {
        m_loopSideEffects[loop->GetIndex()].AddModifiedField(this, fldHnd, fieldKind);
        loop = loop->GetParent();
    } while (loop != nullptr);
}

// Adds "elemType" to the set of modified array element types of "loop" and any parent loops.
void Compiler::AddModifiedElemTypeAllContainingLoops(FlowGraphNaturalLoop* loop, CORINFO_CLASS_HANDLE elemClsHnd)
{
    do
    {
        m_loopSideEffects[loop->GetIndex()].AddModifiedElemType(this, elemClsHnd);
        loop = loop->GetParent();
    } while (loop != nullptr);
}

//------------------------------------------------------------------------------
// optRemoveRangeCheck : Given an indexing node, mark it as not needing a range check.
//
// Arguments:
//    check  -  Range check tree, the raw CHECK node (ARRAY, SIMD or HWINTRINSIC).
//    comma  -  GT_COMMA to which the "check" belongs, "nullptr" if the check is a standalone one.
//    stmt   -  Statement the indexing nodes belong to.
//
// Return Value:
//    Rewritten "check" - no-op if it has no side effects or the tree that contains them.
//
// Notes:
//    This method is capable of removing checks of two kinds: COMMA-based and standalone top-level
//    ones. In case of a COMMA-based check, "check" must be a non-null first operand of a non-null
//    COMMA. In case of a standalone check, "comma" must be null and "check" - "stmt"'s root.
//
//    Does not keep costs or node threading up to date, but does update side effect flags.
//
GenTree* Compiler::optRemoveRangeCheck(GenTreeBoundsChk* check, GenTree* comma, Statement* stmt)
{
#if !REARRANGE_ADDS
    noway_assert(!"can't remove range checks without REARRANGE_ADDS right now");
#endif

    noway_assert(stmt != nullptr);
    noway_assert((comma != nullptr && comma->OperIs(GT_COMMA) && comma->gtGetOp1() == check) ||
                 (check != nullptr && check->OperIs(GT_BOUNDS_CHECK) && comma == nullptr));
    noway_assert(check->OperIs(GT_BOUNDS_CHECK));

    GenTree* tree = comma != nullptr ? comma : check;

#ifdef DEBUG
    if (verbose)
    {
        printf("Before optRemoveRangeCheck:\n");
        gtDispTree(tree);
    }
#endif

    // TODO-Bug: We really should be extracting all side effects from the
    // length and index here, but the length typically involves a GT_ARR_LENGTH
    // that we would preserve. Usually, as part of proving that the range check
    // passes, we have also proven that the ARR_LENGTH is non-faulting. We need
    // a good way to communicate to this function that it is ok to ignore side
    // effects of the ARR_LENGTH.
    GenTree* sideEffList = nullptr;
    gtExtractSideEffList(check->GetArrayLength(), &sideEffList, GTF_ASG);
    gtExtractSideEffList(check->GetIndex(), &sideEffList);

    if (sideEffList != nullptr)
    {
        // We've got some side effects.
        if (tree->OperIs(GT_COMMA))
        {
            // Make the comma handle them.
            tree->AsOp()->gtOp1 = sideEffList;
        }
        else
        {
            // Make the statement execute them instead of the check.
            stmt->SetRootNode(sideEffList);
            tree = sideEffList;
        }
    }
    else
    {
        check->gtBashToNOP();
    }

    if (tree->OperIs(GT_COMMA))
    {
        // TODO-CQ: We should also remove the GT_COMMA, but in any case we can no longer CSE the GT_COMMA.
        tree->gtFlags |= GTF_DONT_CSE;
    }

    gtUpdateSideEffects(stmt, tree);

#ifdef DEBUG
    if (verbose)
    {
        // gtUpdateSideEffects can update the side effects for ancestors in the tree, so display the whole statement
        // tree, not just the sub-tree.
        printf("After optRemoveRangeCheck for [%06u]:\n", dspTreeID(tree));
        gtDispTree(stmt->GetRootNode());
    }
#endif

    return check;
}

//------------------------------------------------------------------------------
// optRemoveStandaloneRangeCheck : A thin wrapper over optRemoveRangeCheck that removes standalone checks.
//
// Arguments:
//    check - The standalone top-level CHECK node.
//    stmt  - The statement "check" is a root node of.
//
// Return Value:
//    If "check" has no side effects, it is retuned, bashed to a no-op.
//    If it has side effects, the tree that executes them is returned.
//
GenTree* Compiler::optRemoveStandaloneRangeCheck(GenTreeBoundsChk* check, Statement* stmt)
{
    assert(check != nullptr);
    assert(stmt != nullptr);
    assert(check == stmt->GetRootNode());

    return optRemoveRangeCheck(check, nullptr, stmt);
}

//------------------------------------------------------------------------------
// optRemoveCommaBasedRangeCheck : A thin wrapper over optRemoveRangeCheck that removes COMMA-based checks.
//
// Arguments:
//    comma - GT_COMMA of which the first operand is the CHECK to be removed.
//    stmt  - The statement "comma" belongs to.
//
void Compiler::optRemoveCommaBasedRangeCheck(GenTree* comma, Statement* stmt)
{
    assert(comma != nullptr && comma->OperIs(GT_COMMA));
    assert(stmt != nullptr);
    assert(comma->gtGetOp1()->OperIs(GT_BOUNDS_CHECK));

    optRemoveRangeCheck(comma->gtGetOp1()->AsBoundsChk(), comma, stmt);
}

/*****************************************************************************
 * Return the scale in an array reference, given a pointer to the
 * multiplication node.
 */

ssize_t Compiler::optGetArrayRefScaleAndIndex(GenTree* mul, GenTree** pIndex DEBUGARG(bool bRngChk))
{
    assert(mul);
    assert(mul->OperIs(GT_MUL) || mul->OperIs(GT_LSH));
    assert(mul->AsOp()->gtOp2->IsCnsIntOrI());

    ssize_t scale = mul->AsOp()->gtOp2->AsIntConCommon()->IconValue();

    if (mul->OperIs(GT_LSH))
    {
        scale = ((ssize_t)1) << scale;
    }

    GenTree* index = mul->AsOp()->gtOp1;

    if (index->OperIs(GT_MUL) && index->AsOp()->gtOp2->IsCnsIntOrI())
    {
        // case of two cascading multiplications for constant int (e.g.  * 20 morphed to * 5 * 4):
        // When index->gtOper is GT_MUL and index->AsOp()->gtOp2->gtOper is GT_CNS_INT (i.e. * 5),
        //     we can bump up the scale from 4 to 5*4, and then change index to index->AsOp()->gtOp1.
        // Otherwise, we cannot optimize it. We will simply keep the original scale and index.
        scale *= index->AsOp()->gtOp2->AsIntConCommon()->IconValue();
        index = index->AsOp()->gtOp1;
    }

    assert(!bRngChk || !index->OperIs(GT_COMMA));

    if (pIndex)
    {
        *pIndex = index;
    }

    return scale;
}

typedef JitHashTable<unsigned, JitSmallPrimitiveKeyFuncs<unsigned>, unsigned> LclVarRefCounts;

//------------------------------------------------------------------------------------------
// optRemoveRedundantZeroInits: Remove redundant zero initializations.
//
// Notes:
//    This phase iterates over basic blocks starting with the first basic block until there is no unique
//    basic block successor or until it detects a loop. It keeps track of local nodes it encounters.
//    When it gets to a store to a local variable or a local field, it checks whether the store
//    is the first reference to the local (or to the parent of the local field), and, if so,
//    it may do one of two optimizations:
//      1. If the following conditions are true:
//            the local is untracked,
//            the value to store is 0,
//            the local is guaranteed to be fully initialized in the prolog,
//         then the explicit zero initialization is removed.
//      2. If the following conditions are true:
//            the store is to a local (and not a field),
//            the local is not lvLiveInOutOfHndlr or no exceptions can be thrown between the prolog and the store,
//            either the local has no gc pointers or there are no gc-safe points between the prolog and the store,
//         then the local is marked with lvHasExplicitInit which tells the codegen not to insert zero initialization
//         for this local in the prolog.
//
void Compiler::optRemoveRedundantZeroInits()
{
#ifdef DEBUG
    if (verbose)
    {
        printf("*************** In optRemoveRedundantZeroInits()\n");
    }
#endif // DEBUG

    CompAllocator   allocator(getAllocator(CMK_ZeroInit));
    LclVarRefCounts refCounts(allocator);
    BitVecTraits    bitVecTraits(lvaCount, this);
    BitVec          zeroInitLocals         = BitVecOps::MakeEmpty(&bitVecTraits);
    bool            hasGCSafePoint         = false;
    bool            hasImplicitControlFlow = false;

    assert(fgNodeThreading == NodeThreading::AllTrees);

    for (BasicBlock* block = fgFirstBB; block != nullptr; block = block->GetUniqueSucc())
    {
        if (m_dfsTree->HasCycle())
        {
            // See if this block is a cycle entry
            //
            bool stop = false;
            for (FlowEdge* predEdge = BlockPredsWithEH(block); predEdge != nullptr;
                 predEdge           = predEdge->getNextPredEdge())
            {
                BasicBlock* const predBlock = predEdge->getSourceBlock();
                if (m_dfsTree->Contains(predBlock) && m_dfsTree->IsAncestor(block, predBlock))
                {
                    JITDUMP(FMT_BB " is part of a cycle, stopping the block scan\n", block->bbNum);
                    stop = true;
                    break;
                }
            }

            // If so, stop looking for redundant zero inits
            //
            if (stop)
            {
                break;
            }
        }

        JITDUMP("Analyzing " FMT_BB "\n", block->bbNum);

        CompAllocator   allocator(getAllocator(CMK_ZeroInit));
        LclVarRefCounts defsInBlock(allocator);
        bool            removedTrackedDefs = false;
        bool            hasEHSuccs         = block->HasPotentialEHSuccs(this);

        for (Statement* stmt = block->FirstNonPhiDef(); stmt != nullptr;)
        {
            Statement* next = stmt->GetNextStmt();
            for (GenTree* const tree : stmt->TreeList())
            {
                hasImplicitControlFlow |= hasEHSuccs && ((tree->gtFlags & GTF_EXCEPT) != 0);
                hasGCSafePoint |= IsPotentialGCSafePoint(tree);

                switch (tree->gtOper)
                {
                    case GT_LCL_VAR:
                    case GT_LCL_FLD:
                    case GT_LCL_ADDR:
                    case GT_STORE_LCL_VAR:
                    case GT_STORE_LCL_FLD:
                    {
                        GenTreeLclVarCommon* lclNode   = tree->AsLclVarCommon();
                        unsigned             lclNum    = lclNode->GetLclNum();
                        unsigned*            pRefCount = refCounts.LookupPointer(lclNum);
                        if (pRefCount != nullptr)
                        {
                            *pRefCount = (*pRefCount) + 1;
                        }
                        else
                        {
                            refCounts.Set(lclNum, 1);
                        }

                        if ((tree->gtFlags & GTF_VAR_DEF) == 0)
                        {
                            break;
                        }

                        // We need to count the number of tracked var defs in the block
                        // so that we can update block->bbVarDef if we remove any tracked var defs.
                        LclVarDsc* const lclDsc = lvaGetDesc(lclNum);
                        if (lclDsc->lvTracked)
                        {
                            unsigned* pDefsCount = defsInBlock.LookupPointer(lclNum);
                            if (pDefsCount != nullptr)
                            {
                                *pDefsCount = (*pDefsCount) + 1;
                            }
                            else
                            {
                                defsInBlock.Set(lclNum, 1);
                            }
                        }
                        // Here we treat both "full" and "partial" tracked field defs as defs
                        // (that is, we ignore the state of GTF_VAR_USEASG).
                        //
                        else if (varTypeIsStruct(lclDsc) && lvaGetPromotionType(lclDsc) != PROMOTION_TYPE_NONE)
                        {
                            for (unsigned i = lclDsc->lvFieldLclStart; i < lclDsc->lvFieldLclStart + lclDsc->lvFieldCnt;
                                 ++i)
                            {
                                if (lvaGetDesc(i)->lvTracked)
                                {
                                    unsigned* pDefsCount = defsInBlock.LookupPointer(i);
                                    if (pDefsCount != nullptr)
                                    {
                                        *pDefsCount = (*pDefsCount) + 1;
                                    }
                                    else
                                    {
                                        defsInBlock.Set(i, 1);
                                    }
                                }
                            }
                        }

                        if (!tree->OperIsLocalStore())
                        {
                            break;
                        }

                        // TODO-Cleanup: there is potential for cleaning this algorithm up by deleting
                        // double lookups of various reference counts. This is complicated somewhat by
                        // the present of LCL_ADDR (GTF_CALL_M_RETBUFFARG_LCLOPT) definitions.
                        pRefCount = refCounts.LookupPointer(lclNum);
                        if (*pRefCount != 1)
                        {
                            break;
                        }

                        unsigned parentRefCount = 0;
                        if (lclDsc->lvIsStructField && refCounts.Lookup(lclDsc->lvParentLcl, &parentRefCount) &&
                            (parentRefCount != 0))
                        {
                            break;
                        }

                        unsigned fieldRefCount = 0;
                        if (lclDsc->lvPromoted)
                        {
                            for (unsigned i = lclDsc->lvFieldLclStart;
                                 (fieldRefCount == 0) && (i < lclDsc->lvFieldLclStart + lclDsc->lvFieldCnt); ++i)
                            {
                                refCounts.Lookup(i, &fieldRefCount);
                            }
                        }

                        if (fieldRefCount != 0)
                        {
                            break;
                        }

                        // The local hasn't been referenced before this store.
                        bool removedExplicitZeroInit = false;
                        bool isEntire                = !tree->IsPartialLclFld(this);

                        if (tree->Data()->IsIntegralConst(0))
                        {
                            bool bbInALoop  = false;
                            bool bbIsReturn = block->KindIs(BBJ_RETURN);

                            if (!bbInALoop || bbIsReturn)
                            {
                                bool neverTracked = lclDsc->IsAddressExposed() || lclDsc->lvPinned ||
                                                    (lclDsc->lvPromoted && varTypeIsStruct(lclDsc));

                                if (BitVecOps::IsMember(&bitVecTraits, zeroInitLocals, lclNum) ||
                                    (lclDsc->lvIsStructField &&
                                     BitVecOps::IsMember(&bitVecTraits, zeroInitLocals, lclDsc->lvParentLcl)) ||
                                    ((neverTracked || !isEntire) &&
                                     !fgVarNeedsExplicitZeroInit(lclNum, bbInALoop, bbIsReturn)))
                                {
                                    // We are guaranteed to have a zero initialization in the prolog or a
                                    // dominating explicit zero initialization and the local hasn't been redefined
                                    // between the prolog and this explicit zero initialization so the store
                                    // can be safely removed.
                                    if (tree == stmt->GetRootNode())
                                    {
                                        fgRemoveStmt(block, stmt);
                                        removedExplicitZeroInit      = true;
                                        lclDsc->lvSuppressedZeroInit = 1;

                                        if (lclDsc->lvTracked)
                                        {
                                            removedTrackedDefs   = true;
                                            unsigned* pDefsCount = defsInBlock.LookupPointer(lclNum);
                                            *pDefsCount          = (*pDefsCount) - 1;
                                        }
                                    }
                                }

                                if (isEntire)
                                {
                                    BitVecOps::AddElemD(&bitVecTraits, zeroInitLocals, lclNum);
                                }
                                *pRefCount = 0;
                            }
                        }

                        if (!removedExplicitZeroInit && isEntire &&
                            (!hasImplicitControlFlow || (lclDsc->lvTracked && !lclDsc->lvLiveInOutOfHndlr)))
                        {
                            // If compMethodRequiresPInvokeFrame() returns true, lower may later
                            // insert a call to CORINFO_HELP_INIT_PINVOKE_FRAME but that is not a gc-safe point.
                            assert(s_helperCallProperties.IsNoGC(CORINFO_HELP_INIT_PINVOKE_FRAME));

                            if (!lclDsc->HasGCPtr() || (!GetInterruptible() && !hasGCSafePoint))
                            {
                                // The local hasn't been used and won't be reported to the gc between
                                // the prolog and this explicit initialization. Therefore, it doesn't
                                // require zero initialization in the prolog.
                                lclDsc->lvHasExplicitInit = 1;
                                lclNode->gtFlags |= GTF_VAR_EXPLICIT_INIT;
                                JITDUMP("Marking V%02u as having an explicit init\n", lclNum);
                            }
                        }
                        break;
                    }
                    default:
                        break;
                }
            }
            stmt = next;
        }

        if (removedTrackedDefs)
        {
            for (const unsigned int lclNum : LclVarRefCounts::KeyIteration(&defsInBlock))
            {
                if (defsInBlock[lclNum] == 0)
                {
                    VarSetOps::RemoveElemD(this, block->bbVarDef, lvaGetDesc(lclNum)->lvVarIndex);
                }
            }
        }
    }
}

//------------------------------------------------------------------------
// optVNBasedDeadStoreRemoval: VN(value)-based dead store removal.
//
// The phase iterates over partial stores referenced by the SSA
// descriptors and deletes those which do not change the local's value.
//
// Return Value:
//    A suitable phase status.
//
PhaseStatus Compiler::optVNBasedDeadStoreRemoval()
{
#ifdef DEBUG
    static ConfigMethodRange JitEnableVNBasedDeadStoreRemovalRange;
    JitEnableVNBasedDeadStoreRemovalRange.EnsureInit(JitConfig.JitEnableVNBasedDeadStoreRemovalRange());

    if (!JitEnableVNBasedDeadStoreRemovalRange.Contains(info.compMethodHash()))
    {
        JITDUMP("VN-based dead store removal disabled by JitEnableVNBasedDeadStoreRemovalRange\n");
        return PhaseStatus::MODIFIED_NOTHING;
    }
#endif

    bool madeChanges = false;

    for (unsigned lclNum = 0; lclNum < lvaCount; lclNum++)
    {
        if (!lvaInSsa(lclNum))
        {
            continue;
        }

        LclVarDsc* varDsc   = lvaGetDesc(lclNum);
        unsigned   defCount = varDsc->lvPerSsaData.GetCount();
        if (defCount <= 1)
        {
            continue;
        }

        if (compIsAsync() && ((varDsc->TypeGet() == TYP_BYREF) ||
                              ((varDsc->TypeGet() == TYP_STRUCT) && varDsc->GetLayout()->HasGCByRef())))
        {
            // A dead store to a byref local may not actually be dead if it
            // crosses a suspension point.
            continue;
        }

        for (unsigned defIndex = 1; defIndex < defCount; defIndex++)
        {
            LclSsaVarDsc*        defDsc = varDsc->lvPerSsaData.GetSsaDefByIndex(defIndex);
            GenTreeLclVarCommon* store  = defDsc->GetDefNode();

            if (store != nullptr)
            {
                assert(store->OperIsLocalStore() && defDsc->m_vnPair.BothDefined());

                JITDUMP("Considering [%06u] for removal...\n", dspTreeID(store));

                if (store->GetLclNum() != lclNum)
                {
                    JITDUMP(" -- no; composite definition\n");
                    continue;
                }

                ValueNum oldStoreValue;
                if ((store->gtFlags & GTF_VAR_USEASG) == 0)
                {
                    LclSsaVarDsc* lastDefDsc = varDsc->lvPerSsaData.GetSsaDefByIndex(defIndex - 1);
                    if (lastDefDsc->GetBlock() != defDsc->GetBlock())
                    {
                        JITDUMP(" -- no; last def not in the same block\n");
                        continue;
                    }

                    if ((store->gtFlags & GTF_VAR_EXPLICIT_INIT) != 0)
                    {
                        // Removing explicit inits is not profitable for primitives and not safe for structs.
                        JITDUMP(" -- no; 'explicit init'\n");
                        continue;
                    }

                    // CQ heuristic: avoid removing defs of enregisterable locals where this is likely to
                    // make them "must-init", extending live ranges. Here we assume the first SSA def was
                    // the implicit "live-in" one, which is not guaranteed, but very likely.
                    if ((defIndex == 1) && !varDsc->TypeIs(TYP_STRUCT))
                    {
                        JITDUMP(" -- no; first explicit def of a non-STRUCT local\n", lclNum);
                        continue;
                    }

                    oldStoreValue = lastDefDsc->m_vnPair.GetConservative();
                }
                else
                {
                    ValueNum oldLclValue = varDsc->GetPerSsaData(defDsc->GetUseDefSsaNum())->m_vnPair.GetConservative();
                    oldStoreValue =
                        vnStore->VNForLoad(VNK_Conservative, oldLclValue, lvaLclExactSize(lclNum), store->TypeGet(),
                                           store->AsLclFld()->GetLclOffs(), store->AsLclFld()->GetSize());
                }

                GenTree* data = store->AsLclVarCommon()->Data();
                ValueNum storeValue;
                if (store->TypeIs(TYP_STRUCT) && data->IsIntegralConst(0))
                {
                    storeValue = vnStore->VNForZeroObj(store->GetLayout(this));
                }
                else
                {
                    storeValue = data->GetVN(VNK_Conservative);
                }

                if (oldStoreValue == storeValue)
                {
                    JITDUMP("Removed dead store:\n");
                    DISPTREE(store);

                    // TODO-ASG: delete this hack.
                    GenTree* nop  = gtNewNothingNode();
                    data->gtNext  = nop;
                    nop->gtPrev   = data;
                    nop->gtNext   = store;
                    store->gtPrev = nop;

                    store->ChangeOper(GT_COMMA);
                    store->AsOp()->gtOp2 = nop;
                    store->gtType        = TYP_VOID;
                    store->SetAllEffectsFlags(data);
                    gtUpdateTreeAncestorsSideEffects(store);

                    madeChanges = true;
                }
                else
                {
                    JITDUMP(" -- no; not redundant\n");
                }
            }
        }
    }

    return madeChanges ? PhaseStatus::MODIFIED_EVERYTHING : PhaseStatus::MODIFIED_NOTHING;
}

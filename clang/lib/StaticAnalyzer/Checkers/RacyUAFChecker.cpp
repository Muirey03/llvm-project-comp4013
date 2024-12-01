#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallDescription.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/Analysis/RetainSummaryManager.h"

// DEBUG:
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"

using namespace clang;
using namespace ento;

namespace {
  class RefVal {
  public:
    RefVal(int cnt) : cnt(cnt) {}
    int getCount() const { return cnt; }

    RefVal operator+(int i) const {
      return RefVal(getCount() + i);
    }

    RefVal operator-(int i) const {
      return RefVal(getCount() - i);
    }

  protected:
    int cnt = 0;
  };

  class RacyUAFChecker : public Checker<check::PostCall> {
  public:
    void checkPostCall(const CallEvent &Call, CheckerContext &C) const;

  private:
    // bug types:
    const BugType DoubleLockBugType{this, "Double locking"};
    const BugType DoubleUnlockBugType{this, "Double unlocking"};

    // maps locking primitives to their respective handlers:
    typedef void (RacyUAFChecker::*FnCheck)(const CallEvent &Call, CheckerContext &C) const;
    CallDescriptionMap<FnCheck> PostCallHandlers = {
      {
        {CDM::CLibrary, {"pthread_mutex_lock"}, 1},
        &RacyUAFChecker::AcquireLock
      },
      {
        {CDM::CLibrary, {"pthread_mutex_unlock"}, 1},
        &RacyUAFChecker::ReleaseLock
      },
    };

    // manager returns a "summary" about what effect a call should have on the receivers' retain counts
    // TODO: subclass RetainSummaryManager to handle code annotations
    mutable std::unique_ptr<RetainSummaryManager> Summaries;

    RetainSummaryManager &getSummaryManager(ASTContext &Ctx) const {
      // only track OSObjects for now:
      if (!Summaries)
        Summaries.reset(new RetainSummaryManager(Ctx, false, true));
      return *Summaries;
    }

    RetainSummaryManager &getSummaryManager(CheckerContext &C) const {
      return getSummaryManager(C.getASTContext());
    }

    // handle locking primitives:
    void AcquireLock(const CallEvent &Call, CheckerContext &C) const;
    void ReleaseLock(const CallEvent &Call, CheckerContext &C) const;

    // handle retain count manipulation:
    void checkSummary(const RetainSummary &Summ, const CallEvent &Call, CheckerContext &C) const;

    // helpers:
    void reportBug(CheckerContext &C, const BugType &bugType, const Expr *MtxExpr, StringRef Desc) const;
  };
} // end anonymous namespace

REGISTER_SET_WITH_PROGRAMSTATE(LockSet, const MemRegion *)
REGISTER_MAP_WITH_PROGRAMSTATE(RefBindings, SymbolRef, RefVal)

void RacyUAFChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  if (const FnCheck *Callback = PostCallHandlers.lookup(Call))
    (this->**Callback)(Call, C);
  else {
    // not a locking primitive, check retain count semantics:
    RetainSummaryManager &Summaries = getSummaryManager(C);
    const Expr *CE = Call.getOriginExpr();
    AnyCall anyCall = CE ? *AnyCall::forExpr(CE) : AnyCall(cast<CXXDestructorDecl>(Call.getDecl()));
    QualType ReceiverType; // ReceiverType is exclusively for ObjC messages. We aren't tracking Obj-C, so leave it null
    const RetainSummary *Summ = Summaries.getSummary(anyCall, Call.hasNonZeroCallbackArg(),false, ReceiverType);
    checkSummary(*Summ, Call, C);
  }
}

void RacyUAFChecker::AcquireLock(const CallEvent &Call, CheckerContext &C) const {
  const Expr *MtxExpr = Call.getArgExpr(0);
  SVal MtxVal = Call.getArgSVal(0);
  const MemRegion *lockR = MtxVal.getAsRegion();

  llvm::dbgs() << "locking: " << lockR << "\n";

  if (!lockR)
    return;

  ProgramStateRef state = C.getState();
  if (state->contains<LockSet>(lockR)) {
    // trying to take a lock that is already taken
    reportBug(C, DoubleLockBugType, MtxExpr, "This lock has already been acquired");
  } else {
    // lock is not already taken, add it to the lockset:
    state = state->add<LockSet>(lockR);
    C.addTransition(state);
  }
}

void RacyUAFChecker::ReleaseLock(const CallEvent &Call, CheckerContext &C) const {
  const Expr *MtxExpr = Call.getArgExpr(0);
  SVal MtxVal = Call.getArgSVal(0);
  const MemRegion *lockR = MtxVal.getAsRegion();

  llvm::dbgs() << "unlocking: " << lockR << "\n";

  if (!lockR)
    return;

  ProgramStateRef state = C.getState();
  if (!state->contains<LockSet>(lockR)) {
    reportBug(C, DoubleUnlockBugType, MtxExpr, "This lock has already been unlocked");
  } else {
    // lock is being released, remove it from the lockset:
    state = state->remove<LockSet>(lockR);
    C.addTransition(state);
  }
}

void RacyUAFChecker::checkSummary(const RetainSummary &Summ, const CallEvent &Call, CheckerContext &C) const {
  // TODO
}

void RacyUAFChecker::reportBug(CheckerContext &C, const BugType &bugType, const Expr *MtxExpr, StringRef Desc) const {
  ExplodedNode *N = C.generateErrorNode();
  if (!N)
    return;
  auto Report = std::make_unique<PathSensitiveBugReport>(bugType, Desc, N);
  Report->addRange(MtxExpr->getSourceRange());
  C.emitReport(std::move(Report));
}

void ento::registerRacyUAFChecker(CheckerManager &mgr) {
  mgr.registerChecker<RacyUAFChecker>();
}

bool ento::shouldRegisterRacyUAFChecker(const CheckerManager &mgr) {
  return true;
}

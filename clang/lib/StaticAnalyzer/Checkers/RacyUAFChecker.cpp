#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallDescription.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"

// DEBUG:
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"

using namespace clang;
using namespace ento;

namespace {
  class RacyUAFChecker : public Checker<check::PostCall> {
  public:
    void checkPostCall(const CallEvent &Call, CheckerContext &C) const;

  private:
    const BugType DoubleLockBugType{this, "Double locking"};
    const BugType DoubleUnlockBugType{this, "Double unlocking"};

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

    void AcquireLock(const CallEvent &Call, CheckerContext &C) const;

    void ReleaseLock(const CallEvent &Call, CheckerContext &C) const;

    void reportBug(CheckerContext &C, const BugType &bugType, const Expr *MtxExpr, StringRef Desc) const;
  };
} // end anonymous namespace

REGISTER_SET_WITH_PROGRAMSTATE(LockSet, const MemRegion *)

void RacyUAFChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  if (const FnCheck *Callback = PostCallHandlers.lookup(Call))
    (this->**Callback)(Call, C);
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

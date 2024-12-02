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
    RefVal(int _cnt, bool _owned) : cnt(_cnt), owned(_owned) {
      // once the refcnt hits 0, the object is no longer owned:
      if (_cnt == 0) {
        setOwned(false);
      }
    }

    static RefVal makeNotOwned() { return RefVal(0, false); }
    static RefVal makeOwned() { return RefVal(1, true); }

    int getCount() const { return cnt; }
    void setCount(const int newCnt) { cnt = newCnt; }
    bool isOwned() const { return owned; } // TODO: do we need to track this separately? can we just return `cnt > 0`?
    void setOwned(const bool newOwned) { owned = newOwned; }

    RefVal operator+(const int i) const {
      return RefVal(cnt + i, owned);
    }

    RefVal operator-(const int i) const {
      return RefVal(cnt - i, owned);
    }

    // required to add to LLVM map:
    bool operator==(const RefVal &X) const {
      return cnt == X.getCount() && owned == X.isOwned();
    }

    void Profile(llvm::FoldingSetNodeID &ID) const {
      ID.AddInteger(cnt);
      ID.AddBoolean(owned);
    }

  protected:
    int cnt = 0;
    bool owned = false;
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

    ProgramStateRef updateSymbol(ProgramStateRef state, SymbolRef sym, RefVal V, ArgEffect E, CheckerContext &C) const;

    // helpers:
    void reportBug(CheckerContext &C, const BugType &bugType, const Expr *MtxExpr, StringRef Desc) const;

    const RefVal *getRefBinding(ProgramStateRef State, SymbolRef Sym) const;

    ProgramStateRef setRefBinding(ProgramStateRef State, SymbolRef Sym, RefVal Val) const;
  };
} // end anonymous namespace

// TODO: is it better to use MemRegions or SymbolRefs for the lockset?
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
    const RetainSummary *Summ = Summaries.getSummary(anyCall, Call.hasNonZeroCallbackArg(), false, ReceiverType);
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

  // DEBUG:
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
  ProgramStateRef state = C.getState();

  // TODO: evaluate effects on arguments

  // evaluate effect on `this`:
  if (const auto *MCall = dyn_cast<CXXMemberCall>(&Call)) {
    if (SymbolRef Sym = MCall->getCXXThisVal().getAsLocSymbol()) {
      if (const RefVal *T = getRefBinding(state, Sym)) {
        state = updateSymbol(state, Sym, *T, Summ.getThisEffect(), C);
      }
    }
  }

  // evaluate effect on the return value:
  RetEffect RE = Summ.getRetEffect();
  if (SymbolRef Sym = Call.getReturnValue().getAsSymbol()) {
    if (RE.notOwned()) {
      state = setRefBinding(state, Sym, RefVal::makeNotOwned());
    } else if (RE.isOwned()) {
      state = setRefBinding(state, Sym, RefVal::makeOwned());
    }
  }

  C.addTransition(state);
}

ProgramStateRef RacyUAFChecker::updateSymbol(ProgramStateRef state, SymbolRef sym, RefVal V, ArgEffect AE,
                                             CheckerContext &C) const {
  // TODO: don't perform update if V is marked as "stop tracking"

  switch (AE.getKind()) {
    case UnretainedOutParameter:
    case RetainedOutParameter:
    case RetainedOutParameterOnZero:
    case RetainedOutParameterOnNonZero:
      // nothing to update for out-params
      return state;

    case Dealloc:
      // TODO: is there any need to track ::free()?
      V.setCount(0);
      V.setOwned(false);

      llvm::dbgs() << "dealloc: " << sym << "\n"; // DEBUG
      break;

    case MayEscape:
      llvm_unreachable("\"MayEscape\" effect unsupported.");

    case DoNothing:
      return state;

    case Autorelease:
      llvm_unreachable("Obj-C autorelease unsupported.");

    case StopTracking:
    case StopTrackingHard:
      // TODO: mark V as no longer tracking
      llvm::dbgs() << "stop tracking: " << sym << "\n"; // DEBUG
      return state;

    case IncRef:
      V = V + 1;
      V.setOwned(true); // TODO: does incrementing the refcnt really mean transfer of ownership?
      llvm::dbgs() << "retain: " << sym << "\n"; // DEBUG
      break;

    case DecRefBridgedTransferred:
      llvm_unreachable("Obj-C bridge_transfer casts unsupported.");

    case DecRef:
    case DecRefAndStopTrackingHard:
      if (V.isOwned()) {
        assert(V.getCount() > 0);

        llvm::dbgs() << "release (owned): " << sym << "\n"; // DEBUG
        if (AE.getKind() == DecRefAndStopTrackingHard) {
          // TODO: mark V as no longer tracking
        }

        // if this drops the refcnt to 0, `owned` will be set to false
        V = V - 1;
      } else {
        llvm::dbgs() << "release (not-owned): " << sym << "\n"; // DEBUG
        if (V.getCount() > 0) {
          if (AE.getKind() == DecRefAndStopTrackingHard) {
            // TODO: mark V as no longer tracking
          }
          V = V - 1;
        } else {
          // TODO: if we're releasing a global object, this won't be a bug
          llvm::dbgs() << "BUG! over-release: " << sym << "\n"; // DEBUG
        }
      }
      break;
  }

  // TODO: report bugs

  return setRefBinding(state, sym, V);
}

void RacyUAFChecker::reportBug(CheckerContext &C, const BugType &bugType, const Expr *MtxExpr, StringRef Desc) const {
  ExplodedNode *N = C.generateErrorNode();
  if (!N)
    return;
  auto Report = std::make_unique<PathSensitiveBugReport>(bugType, Desc, N);
  Report->addRange(MtxExpr->getSourceRange());
  C.emitReport(std::move(Report));
}

const RefVal *RacyUAFChecker::getRefBinding(ProgramStateRef State, SymbolRef Sym) const {
  // TODO: how do we handle untracked symbols?
  //  Do we begin tracking with a new refcnt of 0?
  //  Do we check that an object is "trackable"?
  //  How do we handle malloc/free?
  //  Often our object *WILL* have been allocated by another thread,
  //  so we will necessarily need to begin tracking "on-the-fly"
  return State->get<RefBindings>(Sym);
}

ProgramStateRef RacyUAFChecker::setRefBinding(ProgramStateRef State, SymbolRef Sym, RefVal Val) const {
  assert(Sym != nullptr);
  return State->set<RefBindings>(Sym, Val);
}

void ento::registerRacyUAFChecker(CheckerManager &mgr) {
  mgr.registerChecker<RacyUAFChecker>();
}

bool ento::shouldRegisterRacyUAFChecker(const CheckerManager &mgr) {
  return true;
}

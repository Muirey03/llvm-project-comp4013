// DEBUG:
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"

#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/CheckerManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallDescription.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CallEvent.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/Analysis/RetainSummaryManager.h"
#include <clang/ASTMatchers/ASTMatchers.h>
#include <clang/ASTMatchers/ASTMatchFinder.h>

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
    bool isOwned() const { return owned; }
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

  class LocalRef {
  public:
    LocalRef(bool _safe) : safe(_safe) {}

    // TODO: should this take a set of locks that are protecting the symbol?
    //  This would allow for tracking of `safe` when locks are dropped
    static LocalRef make(const LocalRef *srcLocalRef, const RefVal &srcGlobalRef, bool isLocked) {
      bool srcIsSafe = srcLocalRef ? srcLocalRef->isSafe() : true;
      return LocalRef(srcIsSafe && (isLocked || srcGlobalRef.getCount() > 0));
    }

    bool isSafe() const { return safe; }

    // required to add to LLVM map:
    bool operator==(const LocalRef &X) const {
      return safe == X.isSafe();
    }

    void Profile(llvm::FoldingSetNodeID &ID) const {
      ID.AddBoolean(safe);
    }

  protected:
    bool safe = false;
  };

  class RacyUAFChecker : public Checker<check::PostCall, check::Bind> {
  public:
    void checkPreCall(const CallEvent &Call, CheckerContext &C) const;
    void checkPostCall(const CallEvent &Call, CheckerContext &C) const;
    void checkBind(SVal location, SVal val, const Stmt *S, CheckerContext &C) const;

  private:
    // bug types:
    const BugType DoubleLockBugType{this, "Double locking"};
    const BugType DoubleUnlockBugType{this, "Double unlocking"};
    const BugType IllegalAccessBugType{this, "Illegal variable access"};

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

    // check for race conditions:
    ProgramStateRef checkVariableAccess(ProgramStateRef state, const Expr *Expr, const MemRegion *var, SymbolRef sym, CheckerContext &C) const;

    ProgramStateRef updateSymbol(ProgramStateRef state, const Expr *Expr, SymbolRef sym, RefVal V, ArgEffect E, CheckerContext &C) const;

    // helpers:
    void reportBug(CheckerContext &C, const BugType &bugType, const Expr *Expr, StringRef Desc) const;

    ProgramStateRef getRefBinding(ProgramStateRef State, SymbolRef Sym, const RefVal *&Val) const;

    ProgramStateRef setRefBinding(ProgramStateRef State, SymbolRef Sym, RefVal Val) const;

    bool shouldTrackSymbol(SymbolRef Sym) const;

    bool isSymbolLocked(ProgramStateRef State, SymbolRef Sym) const;

    const MemRegion *getDeclRefExprRegion(ProgramStateRef State, const Expr *Expr, CheckerContext &C) const;
  };
} // end anonymous namespace

// TODO: is it better to use MemRegions or SymbolRefs for the lockset?
REGISTER_SET_WITH_PROGRAMSTATE(LockSet, const MemRegion *)

REGISTER_MAP_WITH_PROGRAMSTATE(RefBindings, SymbolRef, RefVal)

REGISTER_MAP_WITH_PROGRAMSTATE(LocalRefs, const MemRegion *, LocalRef)

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

void RacyUAFChecker::checkBind(SVal dest, SVal src, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef state = C.getState();
  const MemRegion* destVar = dest.getAsRegion();
  if (SymbolRef srcSym = src.getAsLocSymbol()) {
    const RefVal *srcGlobalRef = nullptr;
    state = getRefBinding(state, srcSym, srcGlobalRef);
    if (srcGlobalRef) {
      // if a local ref exists for the src variable, this should be passed to makeForSymbol
      const MemRegion *srcVar = src.getAsRegion();
      const LocalRef *srcLocalRef = nullptr;
      if (srcVar) {
        srcLocalRef = state->get<LocalRefs>(srcVar);
      }

      const LocalRef *oldDestLocalRef = state->get<LocalRefs>(destVar); // DEBUG

      LocalRef destLocalRef = LocalRef::make(srcLocalRef, *srcGlobalRef, isSymbolLocked(state, srcSym));
      state = state->set<LocalRefs>(destVar, destLocalRef);

      llvm::dbgs() << "[checkBind]:\n";
      if (S) {
        if (auto *E = dyn_cast_or_null<BinaryOperator>(S)) {
          const Expr* LHS = E->getLHS();
          if (LHS) {
            llvm::errs() << "\tbind lhs expr: ";
            LHS->dump();

            SVal lhsSval = state->getSVal(LHS, C.getLocationContext());
            const MemRegion *LHSRegion = lhsSval.getAsRegion();
            if (LHSRegion) {
              llvm::dbgs() << "\tbind LHS region: " << LHSRegion << "\n";
            }
          }
        }

      }
      llvm::dbgs() << "\tBinding: " << destVar << " <- " << srcSym << (destLocalRef.isSafe() ? " (safe)\n" : " (unsafe)\n");
      if (oldDestLocalRef) { // DEBUG
        llvm::dbgs() << "\t\t(destination already has a local ref)\n";
      }
    }
    C.addTransition(state);
  }
}

void RacyUAFChecker::AcquireLock(const CallEvent &Call, CheckerContext &C) const {
  const Expr *MtxExpr = Call.getArgExpr(0);
  SVal MtxVal = Call.getArgSVal(0);
  const MemRegion *lockR = MtxVal.getAsRegion();

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

  // evaluate effects on arguments:
  for (unsigned idx = 0, e = Call.getNumArgs(); idx != e; ++idx) {
    SVal V = Call.getArgSVal(idx);
    ArgEffect Effect = Summ.getArg(idx);

    if (SymbolRef Sym = V.getAsLocSymbol()) {
      const RefVal *T = nullptr;
      state = getRefBinding(state, Sym, T);
      if (T) {
        // check that this argument is safe to access:
        const Expr* expr = Call.getArgExpr(idx);
        const MemRegion *argRegion = getDeclRefExprRegion(state, expr, C);
        state = checkVariableAccess(state, expr, argRegion, Sym, C);

        // TODO: when an object is passed to a function as a void*,
        //  RetainCountChecker treats this object as "escaped", and stops tracking it.
        //  Do we want to do the same?
        state = updateSymbol(state, expr, Sym, *T, Effect, C);
      }
    }
  }

  // evaluate effect on receiver:
  if (const auto *MCall = dyn_cast<CXXMemberCall>(&Call)) {
    SVal V = MCall->getCXXThisVal();
    if (SymbolRef Sym = V.getAsLocSymbol()) {
      const RefVal *T = nullptr;
      state = getRefBinding(state, Sym, T);
      if (T) {
        // check that receiver is safe to access:
        const Expr* expr = Call.getOriginExpr();
        const MemRegion *thisRegion = getDeclRefExprRegion(state, expr, C);
        state = checkVariableAccess(state, expr, thisRegion, Sym, C);

        state = updateSymbol(state, Call.getOriginExpr(), Sym, *T, Summ.getThisEffect(), C);
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

ProgramStateRef RacyUAFChecker::checkVariableAccess(ProgramStateRef state, const Expr *Expr, const MemRegion *var, SymbolRef sym, CheckerContext &C) const {
  if (sym) {
    const RefVal *globalRef = state->get<RefBindings>(sym);
    if (globalRef) {
      bool isSafe = globalRef->isOwned() || globalRef->getCount() > 0 || isSymbolLocked(state, sym);

      // if this is a stack variable access, ensure the stack variable is safe too:
      if (var) {
        llvm::dbgs() << "checkVariableAccess(" << var << ")\n";
      }
      if (isSafe && var) {
        const LocalRef *localRef = state->get<LocalRefs>(var);
        if (localRef) {
          llvm::dbgs() << "localRef = " << (localRef->isSafe() ? "safe\n" : "unsafe\n");
          isSafe &= localRef->isSafe();
        }
      }

      if (!isSafe) {
        reportBug(C, IllegalAccessBugType, Expr, "Potential race condition due to illegal access of unlocked variable.");
      }
    }
  }
  return state;
}

ProgramStateRef RacyUAFChecker::updateSymbol(ProgramStateRef state, const Expr *Expr, SymbolRef sym, RefVal V, ArgEffect AE, CheckerContext &C) const {
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
      if (V.isOwned()) {
        // escaping an object converts a stack reference to a global reference:
        V = V - 1;
        V.setOwned(false);
        llvm::dbgs() << "lose ownership: " << sym << "\n"; // DEBUG
        break;
      }
      [[fallthrough]];

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
      llvm::dbgs() << "retain: " << sym << ", owned=" << V.isOwned() << "\n"; // DEBUG
      break;

    case DecRefBridgedTransferred:
      llvm_unreachable("Obj-C bridge_transfer casts unsupported.");

    case DecRef:
    case DecRefAndStopTrackingHard:
      assert(V.getCount() > 0 || !V.isOwned());

      if (AE.getKind() == DecRefAndStopTrackingHard) {
        // TODO: mark V as no longer tracking
      }

      // if this drops the refcnt to 0, `owned` will be set to false
      V = V - 1;
      // we don't report a bug if the refcnt goes below 0,
      //  as we could be releasing some global/unowned object
      break;
  }

  return setRefBinding(state, sym, V);
}

void RacyUAFChecker::reportBug(CheckerContext &C, const BugType &bugType, const Expr *Expr, StringRef Desc) const {
  ExplodedNode *N = C.generateErrorNode();
  if (!N)
    return;
  auto Report = std::make_unique<PathSensitiveBugReport>(bugType, Desc, N);
  Report->addRange(Expr->getSourceRange());
  C.emitReport(std::move(Report));
}

ProgramStateRef RacyUAFChecker::getRefBinding(ProgramStateRef State, SymbolRef Sym, const RefVal *&Val) const {
  const RefVal *V = State->get<RefBindings>(Sym);
  if (!V) {
    if (shouldTrackSymbol(Sym)) {
      State = State->set<RefBindings>(Sym, RefVal::makeNotOwned());
      V = State->get<RefBindings>(Sym);
    }
  }
  Val = V;
  return State;
}

ProgramStateRef RacyUAFChecker::setRefBinding(ProgramStateRef State, SymbolRef Sym, RefVal Val) const {
  assert(Sym != nullptr);
  return State->set<RefBindings>(Sym, Val);
}

static bool isSubclass(const Decl *D, StringRef ClassName) {
  using namespace ast_matchers;
  DeclarationMatcher SubclassM = cxxRecordDecl(isSameOrDerivedFrom(std::string(ClassName)));
  return !(match(SubclassM, *D, D->getASTContext()).empty());
}

bool RacyUAFChecker::shouldTrackSymbol(SymbolRef Sym) const {
  // TODO: how do we handle malloc/free?

  QualType T = Sym->getType();
  if (T->isPointerType()) {
    const Decl *D = Sym->getType()->getPointeeCXXRecordDecl();
    return D && isSubclass(D, "OSMetaClassBase");
  }
  return false;
}

bool RacyUAFChecker::isSymbolLocked(ProgramStateRef State, SymbolRef Sym) const {
  // TODO: for now, assume any lock protects all variables
  return !State->get<LockSet>().isEmpty();
}

const MemRegion *RacyUAFChecker::getDeclRefExprRegion(ProgramStateRef state, const Expr *expr, CheckerContext &C) const {
  expr = expr->IgnoreCasts();
  if (const DeclRefExpr* declExpr = dyn_cast_or_null<DeclRefExpr>(expr)) {
    if (const VarDecl* var = dyn_cast_or_null<VarDecl>(declExpr->getDecl())) {
      const VarRegion* varRegion = state->getRegion(var, C.getLocationContext());
      return varRegion;
    }
  }
  return nullptr;
}

void ento::registerRacyUAFChecker(CheckerManager &mgr) {
  mgr.registerChecker<RacyUAFChecker>();
}

bool ento::shouldRegisterRacyUAFChecker(const CheckerManager &mgr) {
  return true;
}

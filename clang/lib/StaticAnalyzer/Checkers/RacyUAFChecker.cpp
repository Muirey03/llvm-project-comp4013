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

using SmallLockSet = llvm::SmallSet<const MemRegion *, 10>;

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
    LocalRef(bool _safe) : safe(_safe) {
    }

    static LocalRef make(const LocalRef *srcLocalRef, const RefVal &srcGlobalRef, bool isLocked) {
      bool srcIsSafe = srcLocalRef ? srcLocalRef->isSafe() : true;
      return LocalRef(srcIsSafe && (isLocked || srcGlobalRef.getCount() > 0));
    }

    bool isSafe() const { return safe; }

    void markUnsafe() { safe = false; }

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

  class UAFBugVisitor;

  class RacyUAFChecker : public Checker<check::PreCall, check::PostCall, check::Bind> {
    friend class UAFBugVisitor;

  public:
    void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

    void checkPostCall(const CallEvent &Call, CheckerContext &C) const;

    void checkBind(SVal location, SVal val, const Stmt *S, CheckerContext &C) const;

  private:
    // bug types:
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
    ProgramStateRef checkVariableAccess(ProgramStateRef state, const Expr *Expr, const MemRegion *var, SymbolRef sym,
                                        CheckerContext &C) const;

    ProgramStateRef updateSymbol(ProgramStateRef state, const Expr *Expr, SymbolRef sym, RefVal V, ArgEffect E,
                                 CheckerContext &C, bool &didRelease) const;

    ProgramStateRef updateOutParams(ProgramStateRef state, const RetainSummary &Summ, const CallEvent &CE) const;

    ProgramStateRef handleSymbolReleased(ProgramStateRef state, SymbolRef sym) const;

    ProgramStateRef handleSymbolUnlocked(ProgramStateRef state, SymbolRef sym) const;

    ProgramStateRef markReferencesToSymbolUnsafe(ProgramStateRef state, SymbolRef sym) const;

    // helpers:
    void reportBug(CheckerContext &C, const BugType &bugType, const Expr *Expr, const MemRegion *var, SymbolRef sym,
                   StringRef Desc) const;

    ProgramStateRef getRefBinding(ProgramStateRef State, SymbolRef Sym, const RefVal *&Val) const;

    ProgramStateRef setRefBinding(ProgramStateRef State, SymbolRef Sym, RefVal Val) const;

    bool shouldTrackSymbol(SymbolRef Sym) const;

    SmallLockSet findLocksProtectingSymbol(ProgramStateRef State, SymbolRef Sym) const;

    const MemRegion *getDeclRefExprRegion(ProgramStateRef State, const Expr *Expr, CheckerContext &C) const;

    ProgramStateRef markSymbolAsLocked(ProgramStateRef State, SymbolRef Sym,
                                       SmallLockSet lockedBy) const;

    bool isDerivedSymbol(SymbolRef sym, SymbolRef baseSymbol) const;

    const MemSpaceRegion *getSymbolMemorySpace(SymbolRef sym) const;
  };

  class UAFBugVisitor : public BugReporterVisitor {
  public:
    UAFBugVisitor(const RacyUAFChecker &Chk, const MemRegion *var, SymbolRef sym)
      : Chk(Chk), Var(var), Sym(sym) {
    }

    void Profile(llvm::FoldingSetNodeID &ID) const override {
      static int X = 0;
      ID.AddPointer(&X);
      ID.AddPointer(Var);
      ID.AddPointer(Sym);
    }

    PathDiagnosticPieceRef VisitNode(const ExplodedNode *N,
                                     BugReporterContext &BRC,
                                     PathSensitiveBugReport &BR) override;

  private:
    const RacyUAFChecker &Chk;
    const MemRegion *Var;
    const SymbolRef Sym;
  };
} // end anonymous namespace

// TODO: is it better to use MemRegions or SymbolRefs for the lockset?
REGISTER_SET_WITH_PROGRAMSTATE(LockSet, const MemRegion *)

REGISTER_SET_FACTORY_WITH_PROGRAMSTATE(SymbolSet, SymbolRef)

REGISTER_MAP_WITH_PROGRAMSTATE(LockedSymbols, const MemRegion *, SymbolSet)

REGISTER_MAP_WITH_PROGRAMSTATE(RefBindings, SymbolRef, RefVal)

REGISTER_MAP_WITH_PROGRAMSTATE(LocalRefs, const MemRegion *, LocalRef)

void RacyUAFChecker::checkPreCall(const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef state = C.getState();

  // check if arguments are safe to access:
  for (unsigned idx = 0, e = Call.getNumArgs(); idx != e; ++idx) {
    SVal V = Call.getArgSVal(idx);
    if (SymbolRef sym = V.getAsLocSymbol()) {
      const Expr *expr = Call.getArgExpr(idx);
      if (expr) {
        const MemRegion *argRegion = getDeclRefExprRegion(state, expr, C);
        state = checkVariableAccess(state, expr, argRegion, sym, C);
      }
    }
  }

  // check if receiver is safe to access:
  if (const auto *MCall = dyn_cast<CXXMemberCall>(&Call)) {
    SVal V = MCall->getCXXThisVal();
    if (SymbolRef sym = V.getAsLocSymbol()) {
      const Expr *expr = MCall->getCXXThisExpr();
      if (expr) {
        const MemRegion *thisRegion = getDeclRefExprRegion(state, expr, C);
        state = checkVariableAccess(state, expr, thisRegion, sym, C);
      }
    }
  }

  C.addTransition(state);
}

void RacyUAFChecker::checkPostCall(const CallEvent &Call, CheckerContext &C) const {
  if (const FnCheck *Callback = PostCallHandlers.lookup(Call))
    (this->**Callback)(Call, C);
  else {
    // not a locking primitive, check retain count semantics:
    RetainSummaryManager &Summaries = getSummaryManager(C);
    const Expr *CE = Call.getOriginExpr();
    AnyCall anyCall = CE ? *AnyCall::forExpr(CE) : AnyCall(cast<CXXDestructorDecl>(Call.getDecl()));
    QualType ReceiverType; // ReceiverType is exclusively for ObjC messages. We aren't tracking Obj-C, so leave it null
    const RetainSummary *Summ = Summaries.getSummary(anyCall, false /* TODO: why was I getting true here? */, false,
                                                     ReceiverType);
    checkSummary(*Summ, Call, C);
  }
}

void RacyUAFChecker::checkBind(SVal dest, SVal src, const Stmt *S, CheckerContext &C) const {
  ProgramStateRef state = C.getState();
  const MemRegion *destVar = dest.getAsRegion();
  if (SymbolRef srcSym = src.getAsLocSymbol()) {
    const RefVal *srcGlobalRef = nullptr;
    state = getRefBinding(state, srcSym, srcGlobalRef);
    if (srcGlobalRef) {
      // if a local ref exists for the src variable, this should be passed to LocalRef::make
      const MemRegion *srcVar = src.getAsRegion();
      const LocalRef *srcLocalRef = nullptr;
      if (srcVar) {
        srcLocalRef = state->get<LocalRefs>(srcVar);
      }

      // add srcSym to each lock's set of protected symbols
      auto locks = findLocksProtectingSymbol(state, srcSym);
      state = markSymbolAsLocked(state, srcSym, locks);
      LocalRef destLocalRef = LocalRef::make(srcLocalRef, *srcGlobalRef, !locks.empty());
      state = state->set<LocalRefs>(destVar, destLocalRef);
    }
    C.addTransition(state);
  }
}

void RacyUAFChecker::AcquireLock(const CallEvent &Call, CheckerContext &C) const {
  SVal MtxVal = Call.getArgSVal(0);
  const MemRegion *lockR = MtxVal.getAsRegion();

  if (!lockR)
    return;

  ProgramStateRef state = C.getState();
  if (!state->contains<LockSet>(lockR)) {
    // lock is not already taken, add it to the lockset:
    state = state->add<LockSet>(lockR);
    // see comment in handleSymbolReleased as to why we do not
    //  need to populate the lock's set of protected symbols here
    C.addTransition(state);
  }
}

void RacyUAFChecker::ReleaseLock(const CallEvent &Call, CheckerContext &C) const {
  SVal MtxVal = Call.getArgSVal(0);
  const MemRegion *lockR = MtxVal.getAsRegion();

  if (!lockR)
    return;

  ProgramStateRef state = C.getState();
  if (state->contains<LockSet>(lockR)) {
    // lock is being released, remove it from the lockset:
    state = state->remove<LockSet>(lockR);

    // handle the unlocking of all the symbols that this lock was protecting:
    auto *protectedSymbols = state->get<LockedSymbols>(lockR);
    if (protectedSymbols) {
      for (auto it = protectedSymbols->begin(); it != protectedSymbols->end(); ++it) {
        SymbolRef sym = *it;
        state = handleSymbolUnlocked(state, sym);
      }
      state = state->remove<LockedSymbols>(lockR);
    }

    C.addTransition(state);
  }
}

void RacyUAFChecker::checkSummary(const RetainSummary &Summ, const CallEvent &Call, CheckerContext &C) const {
  ProgramStateRef state = C.getState();

  // evaluate effects on arguments:
  for (unsigned idx = 0, e = Call.getNumArgs(); idx != e; ++idx) {
    SVal V = Call.getArgSVal(idx);
    ArgEffect effect = Summ.getArg(idx);

    if (SymbolRef sym = V.getAsLocSymbol()) {
      const RefVal *T = nullptr;
      state = getRefBinding(state, sym, T);
      if (T) {
        // TODO: when an object is passed to a function as a void*,
        //  RetainCountChecker treats this object as "escaped", and stops tracking it.
        //  Do we want to do the same?
        const Expr *expr = Call.getArgExpr(idx);
        bool didRelease = false;
        state = updateSymbol(state, expr, sym, *T, effect, C, didRelease);
        if (didRelease) {
          state = handleSymbolReleased(state, sym);
        }
      }
    }
  }

  // evaluate effect on receiver:
  if (const auto *MCall = dyn_cast<CXXMemberCall>(&Call)) {
    SVal V = MCall->getCXXThisVal();
    if (SymbolRef sym = V.getAsLocSymbol()) {
      const RefVal *T = nullptr;
      state = getRefBinding(state, sym, T);
      if (T) {
        const Expr *expr = MCall->getCXXThisExpr();
        bool didRelease = false;
        state = updateSymbol(state, expr, sym, *T, Summ.getThisEffect(), C, didRelease);
        if (didRelease) {
          state = handleSymbolReleased(state, sym);
        }
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

  // evaluate effect on out parameters:
  state = updateOutParams(state, Summ, Call);

  C.addTransition(state);
}

ProgramStateRef RacyUAFChecker::checkVariableAccess(ProgramStateRef state, const Expr *Expr, const MemRegion *var,
                                                    SymbolRef sym, CheckerContext &C) const {
  if (sym && Expr) {
    const RefVal *globalRef = nullptr;
    state = getRefBinding(state, sym, globalRef);
    if (globalRef) {
      bool isSafe = globalRef->isOwned() || globalRef->getCount() > 0 || !findLocksProtectingSymbol(state, sym).
                    empty();

      // if this is a stack variable access, ensure the stack variable is safe too:
      if (isSafe && var) {
        const LocalRef *localRef = state->get<LocalRefs>(var);
        if (localRef) {
          isSafe &= localRef->isSafe();
        }
      }

      if (!isSafe) {
        reportBug(C, IllegalAccessBugType, Expr, var, sym,
                  "Potential race condition due to access of unsafe variable.");
      }
    }
  }
  return state;
}

ProgramStateRef RacyUAFChecker::updateSymbol(ProgramStateRef state, const Expr *Expr, SymbolRef sym, RefVal V,
                                             ArgEffect AE, CheckerContext &C, bool &didRelease) const {
  // TODO: don't perform update if V is marked as "stop tracking"

  int oldCount = V.getCount();

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
        // TODO: revisit this
        // escaping an object converts a stack reference to a global reference:
        V = V - 1;
        V.setOwned(false);
        // llvm::dbgs() << "lose ownership: " << sym << "\n"; // DEBUG
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
      // llvm::dbgs() << "stop tracking: " << sym << "\n"; // DEBUG
      return state;

    case IncRef:
      V = V + 1;
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

  // if this symbol just lost all its stack references, and it is unlocked,
  //  then we need to mark all the local references to it as unsafe
  int newCount = V.getCount();
  if (newCount < oldCount && newCount <= 0) {
    didRelease = true;
  }

  return setRefBinding(state, sym, V);
}

ProgramStateRef RacyUAFChecker::updateOutParams(ProgramStateRef state, const RetainSummary &Summ,
                                                const CallEvent &CE) const {
  for (unsigned idx = 0, e = CE.getNumArgs(); idx != e; ++idx) {
    SVal ArgVal = CE.getArgSVal(idx);
    ArgEffect AE = Summ.getArg(idx);

    auto *ArgRegion = dyn_cast_or_null<TypedValueRegion>(ArgVal.getAsRegion());
    if (!ArgRegion)
      continue;

    SVal PointeeVal = state->getSVal(ArgRegion);
    SymbolRef Sym = PointeeVal.getAsLocSymbol();
    if (!Sym)
      continue;

    // TODO: handle splitting on return value correctly
    if (AE.getKind() == UnretainedOutParameter) {
      state = setRefBinding(state, Sym, RefVal::makeNotOwned());
    } else if (AE.getKind() == RetainedOutParameter || AE.getKind() == RetainedOutParameterOnZero || AE.getKind() ==
               RetainedOutParameterOnNonZero) {
      state = setRefBinding(state, Sym, RefVal::makeOwned());
    }
  }
  return state;
}

ProgramStateRef RacyUAFChecker::handleSymbolReleased(ProgramStateRef state, SymbolRef sym) const {
  // DEBUG:
  const RefVal *globalRef = nullptr;
  state = getRefBinding(state, sym, globalRef);
  assert(sym && globalRef && globalRef->getCount() <= 0);

  // if this symbol is unlocked, we need to mark the references to it as unsafe:
  auto locks = findLocksProtectingSymbol(state, sym);
  if (locks.empty()) {
    state = markReferencesToSymbolUnsafe(state, sym);
  } else {
    // in order for the lock to be the last item keeping a reference safe, then either:
    //  - the reference was made during the lock
    //  - the object was released while locked
    // Add sym to lock's set of protected symbols:
    state = markSymbolAsLocked(state, sym, locks);
  }
  return state;
}

ProgramStateRef RacyUAFChecker::handleSymbolUnlocked(ProgramStateRef state, SymbolRef sym) const {
  // this symbol may have been protected by multiple variables, so check that is really is unlocked:
  auto locks = findLocksProtectingSymbol(state, sym);
  if (!locks.empty()) {
    return state;
  }

  // if this symbol has 0 refcnt, we need to mark the references to it as unsafe:
  const RefVal *globalRef = nullptr;
  state = getRefBinding(state, sym, globalRef);
  if (globalRef && globalRef->getCount() <= 0) {
    state = markReferencesToSymbolUnsafe(state, sym);
  }
  return state;
}

ProgramStateRef RacyUAFChecker::markReferencesToSymbolUnsafe(ProgramStateRef state, SymbolRef sym) const {
  auto localRefs = state->get<LocalRefs>();
  for (auto it = localRefs.begin(); it != localRefs.end(); ++it) {
    auto [memRegion, localRef] = *it;

    // skip references that are already unsafe:
    if (!localRef.isSafe()) {
      continue;
    }

    // if this variable references sym, mark it as unsafe:
    SVal localRefSVal = state->getSVal(memRegion);
    SymbolRef localRefSym = localRefSVal.getAsLocSymbol();
    // instead of checking for exact equality here, check if the localRefSymbol is *encapsulated* within sym.
    //  this way, we also mark object's fields that were stored on the stack as unsafe
    if (localRefSym && isDerivedSymbol(localRefSym, sym)) {
      localRef.markUnsafe();
      state = state->set<LocalRefs>(memRegion, localRef);
    }
  }
  return state;
}

void RacyUAFChecker::reportBug(CheckerContext &C, const BugType &bugType, const Expr *Expr, const MemRegion *var,
                               SymbolRef sym, StringRef Desc) const {
  ExplodedNode *N = C.generateErrorNode();
  if (!N)
    return;
  auto Report = std::make_unique<PathSensitiveBugReport>(bugType, Desc, N);
  Report->addRange(Expr->getSourceRange());
  Report->addVisitor(std::make_unique<UAFBugVisitor>(*this, var, sym));
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
  // DEBUG
  // TODO: how do we handle malloc/free?
  QualType T = Sym->getType();
  if (T->isPointerType()) {
    const Decl *cxxD = T->getPointeeCXXRecordDecl();
    if (cxxD) {
      return isSubclass(cxxD, "OSMetaClassBase");
    }

    QualType pointeeT = T->getPointeeType();
    if (pointeeT->isStructureType()) {
      const RecordDecl *strucD = pointeeT->getAsRecordDecl();
      if (strucD && strucD->getName() == "_DEVMEMINT_CTX_") {
        return true;
      }
    }
  }
  return false;
}

SmallLockSet RacyUAFChecker::findLocksProtectingSymbol(ProgramStateRef State,
                                                       SymbolRef sym) const {
  SmallLockSet locks;

  // TODO: optimisation: we only need to get the symbol memory space when we first encounter a global lock
  //  ie. when lockR->getSymbolicBase() == nullptr
  const MemSpaceRegion *symMemSpace = getSymbolMemorySpace(sym);

  llvm::ImmutableSet<const MemRegion *> allLocks = State->get<LockSet>();
  for (const MemRegion *lockR: allLocks) {
    const SymbolicRegion *lockSymBase;
    if ((lockSymBase = lockR->getSymbolicBase())) {
      // if lock is a member of a symbolic region, sym is locked if it is derived from that region's symbol
      SymbolRef lockedSym = lockSymBase->getSymbol();
      if (isDerivedSymbol(sym, lockedSym)) {
        locks.insert(lockR);
      }
    } else if (symMemSpace) {
      // if lock is a global region, sym is locked if it is derived from a global region in the same translation unit
      // TODO: optimisation: lockR cannot be a subregion of symMemSpace is symMemSpace is "Unknown"
      if (lockR->isSubRegionOf(symMemSpace)) {
        locks.insert(lockR);
      }
    }
  }

  // TODO: should this function call markSymbolAsLocked instead of being the caller's responsibility?
  return locks;
}

const MemRegion *
RacyUAFChecker::getDeclRefExprRegion(ProgramStateRef state, const Expr *expr, CheckerContext &C) const {
  expr = expr->IgnoreCasts();
  if (const DeclRefExpr *declExpr = dyn_cast_or_null<DeclRefExpr>(expr)) {
    if (const VarDecl *var = dyn_cast_or_null<VarDecl>(declExpr->getDecl())) {
      const VarRegion *varRegion = state->getRegion(var, C.getLocationContext());
      return varRegion;
    }
  }
  return nullptr;
}

ProgramStateRef RacyUAFChecker::markSymbolAsLocked(ProgramStateRef State, SymbolRef Sym,
                                                   SmallLockSet lockedBy) const {
  for (auto it = lockedBy.begin(); it != lockedBy.end(); ++it) {
    const MemRegion *lock = *it;
    const SymbolSet *oldProtectedSymbols = State->get<LockedSymbols>(lock);
    SymbolSet::Factory &F = State->getStateManager().get_context<SymbolSet>();

    if (oldProtectedSymbols) {
      State = State->set<LockedSymbols>(lock, F.add(*oldProtectedSymbols, Sym));
    } else {
      State = State->set<LockedSymbols>(lock, F.add(F.getEmptySet(), Sym));
    }
  }
  return State;
}

bool RacyUAFChecker::isDerivedSymbol(SymbolRef sym, SymbolRef baseSymbol) const {
  while (sym) {
    if (sym == baseSymbol) {
      return true;
    }

    SymbolRef parentSym = nullptr;
    const MemRegion *originR = sym->getOriginRegion();
    if (originR) {
      const SymbolicRegion *symbolicBase = originR->getSymbolicBase();
      if (symbolicBase) {
        parentSym = symbolicBase->getSymbol();
      }
    }
    if (parentSym == sym) {
      llvm::errs() << "Parent of " << sym << " is itself?!\n";
      parentSym = nullptr;
    }

    sym = parentSym;
  }

  return false;
}

const MemSpaceRegion *RacyUAFChecker::getSymbolMemorySpace(SymbolRef sym) const {
  const MemRegion *R = sym->getOriginRegion();
  const MemSpaceRegion *space = nullptr;
  while (R) {
    space = dyn_cast_or_null<MemSpaceRegion>(R);

    const SymbolicRegion *symR;
    const SubRegion *subR;

    if (((symR = dyn_cast_or_null<SymbolicRegion>(R))) && ((sym = symR->getSymbol()))) {
      R = sym->getOriginRegion();
    } else if ((subR = dyn_cast_or_null<SubRegion>(R))) {
      R = subR->getSuperRegion();
    } else {
      break;
    }
  }
  return space;
}

static const MemRegion *unwrapRValueReferenceIndirection(const MemRegion *MR) {
  if (const auto *SR = dyn_cast_or_null<SymbolicRegion>(MR)) {
    SymbolRef Sym = SR->getSymbol();
    if (Sym->getType()->isRValueReferenceType())
      if (const MemRegion *OriginMR = Sym->getOriginRegion())
        return OriginMR;
  }
  return MR;
}

static void explainObject(llvm::raw_ostream &OS, const MemRegion *MR) {
  if (const auto DR = dyn_cast_or_null<DeclRegion>(unwrapRValueReferenceIndirection(MR))) {
    const auto *RegionDecl = cast<NamedDecl>(DR->getDecl());
    OS << "'" << RegionDecl->getDeclName() << "'";
  } else {
    OS << MR->getDescriptiveName(true);
  }
}

PathDiagnosticPieceRef UAFBugVisitor::VisitNode(const ExplodedNode *N, BugReporterContext &BRC,
                                                PathSensitiveBugReport &BR) {
  const Stmt *S = N->getStmtForDiagnostics();
  if (!S)
    return nullptr;

  SmallString<128> Str;
  llvm::raw_svector_ostream OS(Str);

  bool reported = false;
  ProgramStateRef State = N->getState();
  ProgramStateRef StatePrev = N->getFirstPred()->getState();

  if (Var) {
    const LocalRef *newLocalRef = State->get<LocalRefs>(Var);
    const LocalRef *oldLocalRef = StatePrev->get<LocalRefs>(Var);
    if (newLocalRef) {
      bool newSafe = newLocalRef->isSafe();
      if (!oldLocalRef) {
        OS << (newSafe ? "Safe" : "Unsafe") << " reference ";
        explainObject(OS, Var);
        OS << " taken";
        reported = true;
      } else {
        bool oldSafe = oldLocalRef->isSafe();
        if (oldSafe && !newSafe) {
          explainObject(OS, Var);
          OS << " marked as unsafe";
          reported = true;
        }
      }
    }
  }

  if (!reported) {
    const RefVal *newRef = State->get<RefBindings>(Sym);
    const RefVal *oldRef = StatePrev->get<RefBindings>(Sym);
    if (newRef) {
      int newCnt = newRef->getCount();
      if (!oldRef) {
        OS << "Object first referenced";
        reported = true;
      } else {
        int oldCnt = oldRef->getCount();
        if (oldCnt < newCnt) {
          OS << "Object retained";
          reported = true;
        } else if (oldCnt > newCnt) {
          OS << "Object released";
          reported = true;
        }
      }
    }
  }

  if (!reported) {
    SmallLockSet oldLocks = Chk.findLocksProtectingSymbol(StatePrev, Sym);
    SmallLockSet newLocks = Chk.findLocksProtectingSymbol(State, Sym);
    auto oldLockCnt = oldLocks.size();
    auto newLockCnt = newLocks.size();
    if (oldLockCnt < newLockCnt) {
      OS << "Lock aquired";
      reported = true;
    } else if (oldLockCnt > newLockCnt) {
      OS << "Lock dropped";
      reported = true;
    }
  }

  if (!reported) {
    return nullptr;
  }

  PathDiagnosticLocation Pos(S, BRC.getSourceManager(), N->getLocationContext());
  return std::make_shared<PathDiagnosticEventPiece>(Pos, OS.str(), true);
}

void ento::registerRacyUAFChecker(CheckerManager &mgr) {
  mgr.registerChecker<RacyUAFChecker>();
}

bool ento::shouldRegisterRacyUAFChecker(const CheckerManager &mgr) {
  return true;
}

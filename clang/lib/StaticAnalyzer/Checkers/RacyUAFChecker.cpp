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
#include "Yaml.h"
#include "llvm/Support/YAMLTraits.h"
#include "llvm/Support/JSON.h"

using namespace clang;
using namespace ento;

namespace {
  using SmallLockSet = llvm::SmallSet<const MemRegion *, 10>;

  struct OwnershipTrackedAttr {
    static bool classof(const Attr *A) {
      if (auto AA = dyn_cast<AnnotateAttr>(A))
        return AA->getAnnotation() == "rc_ownership_tracked";
      return false;
    }
  };

  struct ThreadEntrypointAttr {
    static bool classof(const Attr *A) {
      if (auto AA = dyn_cast<AnnotateAttr>(A))
        return AA->getAnnotation() == "thread_entrypoint";
      return false;
    }
  };

  struct SharedResourceAttr {
    static bool classof(const Attr *A) {
      if (auto AA = dyn_cast<AnnotateAttr>(A))
        return AA->getAnnotation() == "shared_resource";
      return false;
    }
  };

  // fake CallExpr to use with CallDescriptions when a real CallExpr is not available:
  class DummyFunctionCall : public AnyFunctionCall {
  public:
    DummyFunctionCall(const Decl *D) : AnyFunctionCall(D, nullptr, nullptr, CFGBlock::ConstCFGElementRef(nullptr, 0)) {
    }

    void cloneTo(void *Dest) const override { assert(false); }
    Kind getKind() const override { return CE_Function; }
    StringRef getKindAsString() const override { return "DummyFunctionCall"; }
    unsigned getNumArgs() const override { return 0; }
  };

  class RefVal {
  public:
    RefVal(int _cnt, bool _unknownOrigin = false)
      : cnt(_cnt), unknownOrigin(_unknownOrigin) {
    }

    RefVal() : unknownOrigin(true) {
    }

    static RefVal makeUnretained() { return RefVal(0, false); }
    static RefVal makeRetained() { return RefVal(1, false); }
    static RefVal makeUnknownOrigin() { return RefVal(); }

    int getCount() const { return cnt; }
    void setCount(const int newCnt) { cnt = newCnt; }
    bool hasUnknownOrigin() const { return unknownOrigin; }

    RefVal operator+(const int i) const {
      return RefVal(cnt + i, unknownOrigin);
    }

    RefVal operator-(const int i) const {
      return RefVal(cnt - i, unknownOrigin);
    }

    // required to add to LLVM map:
    bool operator==(const RefVal &X) const {
      return cnt == X.getCount() && unknownOrigin == X.hasUnknownOrigin();
    }

    void Profile(llvm::FoldingSetNodeID &ID) const {
      ID.AddInteger(cnt);
      ID.AddBoolean(unknownOrigin);
    }

  protected:
    int cnt = 0;
    bool unknownOrigin = false;
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

  /// Used to parse the configuration file.
  struct RacyUAFConfiguration {
    std::vector<std::string> Entries;
    bool DumpCoverage = false;

    RacyUAFConfiguration() = default;

    RacyUAFConfiguration(const RacyUAFConfiguration &) = default;

    RacyUAFConfiguration(RacyUAFConfiguration &&) = default;

    RacyUAFConfiguration &operator=(const RacyUAFConfiguration &) = default;

    RacyUAFConfiguration &operator=(RacyUAFConfiguration &&) = default;
  };

  class UAFBugVisitor;

  struct CoverageData {
    std::map<std::string, std::map<unsigned, unsigned> > visitedLines;
  };

  class RacyUAFChecker : public Checker<check::BeginFunction, check::PreCall, check::PostCall, check::Bind,
        eval::Call, check::PreStmt<Stmt>,
        check::EndOfTranslationUnit> {
    friend class UAFBugVisitor;

  public:
    void parseConfigFile(CheckerManager &mgr, StringRef configFile);

    void checkBeginFunction(CheckerContext &C) const;

    void checkPreCall(const CallEvent &Call, CheckerContext &C) const;

    void checkPostCall(const CallEvent &Call, CheckerContext &C) const;

    void checkBind(SVal location, SVal val, const Stmt *S, CheckerContext &C) const;

    bool evalCall(const CallEvent &Call, CheckerContext &C) const;

    void checkPreStmt(const Stmt *S, CheckerContext &C) const;

    void checkEndOfTranslationUnit(const TranslationUnitDecl *TU, AnalysisManager &mgr, BugReporter &BR) const;

  private:
    // bug types:
    const BugType IllegalAccessBugType{this, "Illegal variable access"};

    // locking semantics:
    enum LockingSemantics { NotApplicable = 0, PthreadSemantics, XNUSemantics };

    // maps locking primitives to their respective handlers:
    typedef void (RacyUAFChecker::*FnCheck)(const CallEvent &Call, CheckerContext &C) const;

    CallDescriptionMap<FnCheck> PostCallHandlers = {
      // Acquire.
      {
        {CDM::CLibrary, {"pthread_mutex_lock"}, 1},
        &RacyUAFChecker::AcquirePthreadLock
      },
      {
        {CDM::CLibrary, {"pthread_rwlock_rdlock"}, 1},
        &RacyUAFChecker::AcquirePthreadLock
      },
      {
        {CDM::CLibrary, {"pthread_rwlock_wrlock"}, 1},
        &RacyUAFChecker::AcquirePthreadLock
      },
      {
        {CDM::CLibrary, {"lck_mtx_lock"}, 1},
        &RacyUAFChecker::AcquireXNULock
      },
      {
        {CDM::CLibrary, {"lck_ticket_lock"}, 1},
        &RacyUAFChecker::AcquireXNULock
      },
      {
        {CDM::CLibrary, {"lck_rw_lock_exclusive"}, 1},
        &RacyUAFChecker::AcquireXNULock
      },
      {
        {CDM::CLibrary, {"lck_rw_lock_shared"}, 1},
        &RacyUAFChecker::AcquireXNULock
      },

      // Try.
      {
        {CDM::CLibrary, {"pthread_mutex_trylock"}, 1},
        &RacyUAFChecker::TryPthreadLock
      },
      {
        {CDM::CLibrary, {"pthread_rwlock_tryrdlock"}, 1},
        &RacyUAFChecker::TryPthreadLock
      },
      {
        {CDM::CLibrary, {"pthread_rwlock_trywrlock"}, 1},
        &RacyUAFChecker::TryPthreadLock
      },
      {
        {CDM::CLibrary, {"lck_mtx_try_lock"}, 1},
        &RacyUAFChecker::TryXNULock
      },
      {
        {CDM::CLibrary, {"lck_rw_try_lock_exclusive"}, 1},
        &RacyUAFChecker::TryXNULock
      },
      {
        {CDM::CLibrary, {"lck_rw_try_lock_shared"}, 1},
        &RacyUAFChecker::TryXNULock
      },

      // Release.
      {
        {CDM::CLibrary, {"pthread_mutex_unlock"}, 1},
        &RacyUAFChecker::ReleaseLock
      },
      {
        {CDM::CLibrary, {"pthread_rwlock_unlock"}, 1},
        &RacyUAFChecker::ReleaseLock
      },
      {
        {CDM::CLibrary, {"lck_mtx_unlock"}, 1},
        &RacyUAFChecker::ReleaseLock
      },
      {
        {CDM::CLibrary, {"lck_ticket_unlock"}, 1},
        &RacyUAFChecker::ReleaseLock
      },
      {
        {CDM::CLibrary, {"lck_rw_unlock_exclusive"}, 1},
        &RacyUAFChecker::ReleaseLock
      },
      {
        {CDM::CLibrary, {"lck_rw_unlock_shared"}, 1},
        &RacyUAFChecker::ReleaseLock
      },
      {
        {CDM::CLibrary, {"lck_rw_done"}, 1},
        &RacyUAFChecker::ReleaseLock
      },
    };

    CallDescriptionSet TrustedRCImplementations = {
      {CDM::CXXMethod, {"libkern", "intrusive_shared_ptr", "intrusive_shared_ptr"}},
      {CDM::CXXMethod, {"libkern", "intrusive_shared_ptr", "~intrusive_shared_ptr"}},
      {CDM::CXXMethod, {"libkern", "intrusive_shared_ptr", "operator="}},
      {CDM::CXXMethod, {"libkern", "intrusive_shared_ptr", "reset"}},
    };

    CallDescriptionSet SkippedFunctionBodies = {
      {CDM::CLibrary, {"mutex_pause"}, 1},
      {CDM::CLibrary, {"panic"}},
      {CDM::CLibrary, {"ipc_port_release_send"}},
      {CDM::CLibrary, {"vm_shared_region_deallocate"}},
      {CDM::CLibrary, {"ipc_kmsg_free"}},
    };

    // singleton classes:
#define CLASS_MATCH(name) ast_matchers::isSameOrDerivedFrom(std::string(name))
    ast_matchers::internal::BindableMatcher<Decl> SingletonMatcher =
        ast_matchers::cxxRecordDecl(ast_matchers::anyOf(
          CLASS_MATCH("OSMetaClass"),
          CLASS_MATCH("OSSymbol"),
          CLASS_MATCH("OSBoolean"),
          CLASS_MATCH("IOCatalogue")
        ));
#undef CLASS_MATCH

    // config:
    std::optional<CallDescriptionMap<bool> > ExtraEntries;
    bool DumpCoverage = false;

    // coverage information:
    mutable CoverageData Coverage;

    // manager returns a "summary" about what effect a call should have on the receivers' retain counts
    mutable std::unique_ptr<RetainSummaryManager> Summaries;

    bool isEntry(const AnyCall &Call, CheckerContext &C) const;

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
    void AcquireLockAux(const CallEvent &Call, CheckerContext &C, SVal MtxVal, bool IsTryLock,
                        enum LockingSemantics Semantics) const;

    void AcquirePthreadLock(const CallEvent &Call, CheckerContext &C) const;

    void AcquireXNULock(const CallEvent &Call, CheckerContext &C) const;

    void TryPthreadLock(const CallEvent &Call, CheckerContext &C) const;

    void TryXNULock(const CallEvent &Call, CheckerContext &C) const;

    void ReleaseLock(const CallEvent &Call, CheckerContext &C) const;

    // handle retain count manipulation:
    void checkSummary(const RetainSummary &Summ, const CallEvent &Call, CheckerContext &C) const;

    // check for race conditions:
    ProgramStateRef checkVariableAccess(ProgramStateRef state, const Expr *Expr, const MemRegion *var, SymbolRef sym,
                                        CheckerContext &C) const;

    ProgramStateRef updateSymbol(ProgramStateRef state, const Expr *Expr, SymbolRef sym, RefVal V, ArgEffect E,
                                 CheckerContext &C, bool &didRelease) const;

    ProgramStateRef handleSymbolReleased(ProgramStateRef state, SymbolRef sym) const;

    ProgramStateRef handleSymbolUnlocked(ProgramStateRef state, SymbolRef sym) const;

    ProgramStateRef markReferencesToSymbolUnsafe(ProgramStateRef state, SymbolRef sym) const;

    // helpers:
    void reportBug(CheckerContext &C, const BugType &bugType, const Expr *Expr, const MemRegion *var, SymbolRef sym,
                   StringRef Desc) const;

    ProgramStateRef getRefBinding(ProgramStateRef State, SymbolRef Sym, const RefVal *&Val) const;

    ProgramStateRef setRefBinding(ProgramStateRef State, SymbolRef Sym, RefVal Val) const;

    ProgramStateRef createRefBinding(ProgramStateRef State, SymbolRef Sym) const;

    RecordDecl *getSymbolPointeeTypeDecl(SymbolRef sym) const;

    RecordDecl *getRegionPointeeTypeDecl(const MemRegion *R) const;

    bool shouldTrackSymbol(SymbolRef Sym) const;

    bool isSingletonType(Decl *D) const;

    bool isSingletonRegion(const MemRegion *R) const;

    SmallLockSet findLocksProtectingSymbol(ProgramStateRef State, SymbolRef Sym) const;

    const MemRegion *getDeclRefExprRegion(ProgramStateRef State, const Expr *Expr, CheckerContext &C) const;

    ProgramStateRef markSymbolAsLocked(ProgramStateRef State, SymbolRef Sym,
                                       SmallLockSet lockedBy) const;

    SymbolRef getParentSymbol(SymbolRef sym) const;

    const MemRegion *getParentRegion(const MemRegion *R) const;

    bool isDerivedSymbol(SymbolRef sym, SymbolRef baseSymbol) const;

    const MemSpaceRegion *getSymbolMemorySpace(SymbolRef sym) const;

    const SmallString<128> createBugDescription(CheckerContext &C, const MemRegion *var, SymbolRef sym) const;
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

REGISTER_SET_WITH_PROGRAMSTATE(LockSet, const MemRegion *)

REGISTER_SET_FACTORY_WITH_PROGRAMSTATE(SymbolSet, SymbolRef)

REGISTER_MAP_WITH_PROGRAMSTATE(LockedSymbols, const MemRegion *, SymbolSet)

REGISTER_MAP_WITH_PROGRAMSTATE(RefBindings, SymbolRef, RefVal)

REGISTER_MAP_WITH_PROGRAMSTATE(LocalRefs, const MemRegion *, LocalRef)

REGISTER_SET_WITH_PROGRAMSTATE(EntryArguments, SymbolRef)

// YAML config parsing:
namespace llvm {
  namespace yaml {
    template<>
    struct MappingTraits<RacyUAFConfiguration> {
      static void mapping(IO &IO, RacyUAFConfiguration &Config) {
        IO.mapOptional("Entrypoints", Config.Entries);
        IO.mapOptional("DumpCoverage", Config.DumpCoverage);
      }
    };
  }
}

void RacyUAFChecker::checkBeginFunction(CheckerContext &C) const {
  const LocationContext *LC = C.getLocationContext();
  const Decl *D = LC ? LC->getDecl() : nullptr;
  std::optional<AnyCall> Call = AnyCall::forDecl(D);

  bool inTopFrame = C.inTopFrame();
  if (inTopFrame) {
    if (!Call || !isEntry(*Call, C)) {
      C.addSink();
      return;
    }
  }

  if (!Call)
    return;

  ProgramStateRef state = C.getState();
  for (unsigned idx = 0, e = Call->param_size(); idx != e; ++idx) {
    const ParmVarDecl *Param = Call->parameters()[idx];
    SymbolRef Sym = state->getSVal(state->getRegion(Param, LC)).getAsLocSymbol();
    if (!Sym) continue;

    // if we are in the top frame, the symbol needs to be added to the set of entry arguments
    if (inTopFrame)
      state = state->add<EntryArguments>(Sym);

    // arguments should be retained if not already tracked:
    //  (arguments are unlikely to be untracked if this is not in the top frame, but it is possible)
    if (!state->get<RefBindings>(Sym) && shouldTrackSymbol(Sym)) {
      state = setRefBinding(state, Sym, RefVal::makeRetained());
    }
  }
  C.addTransition(state);
}

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
  if (TrustedRCImplementations.contains(Call)) {
    return;
  }

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
  if (!destVar) return;

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
  } else if (SymbolRef dstSym = state->getSVal(destVar).getAsLocSymbol()) {
    if (dstSym != srcSym) {
      const RefVal *destGlobalRef = nullptr;
      state = getRefBinding(state, dstSym, destGlobalRef);
      if (destGlobalRef) {
        const MemSpaceRegion *destSpace = destVar->getMemorySpace();
        if (!isa<StackSpaceRegion>(destSpace)) {
          state = setRefBinding(state, dstSym, *destGlobalRef + 1);
        }
      }
    }
  }
  C.addTransition(state);
}

bool RacyUAFChecker::evalCall(const CallEvent &Call, CheckerContext &C) const {
  // do not evaluate locking primitives implementations or skipped bodies:
  if (SkippedFunctionBodies.contains(Call) || PostCallHandlers.lookup(Call))
    return true;
  return false;
}

bool RacyUAFChecker::isEntry(const AnyCall &Call, CheckerContext &C) const {
  const Decl *D = Call.getDecl();
  if (D && D->hasAttr<ThreadEntrypointAttr>())
    return true;
  if (ExtraEntries) {
    DummyFunctionCall CE(D);
    return !!ExtraEntries->lookup(CE);
  }
  return false;
}

void RacyUAFChecker::parseConfigFile(CheckerManager &mgr, StringRef configFile) {
  std::optional<RacyUAFConfiguration> Config = getConfiguration<RacyUAFConfiguration>(mgr, this, "Config", configFile);

  std::vector<std::pair<CallDescription, bool> > entries;
  for (std::string fnname: Config->Entries) {
    entries.emplace_back(CallDescription(CDM::Unspecified, {fnname}), true);
  }
  ExtraEntries.emplace(
    std::make_move_iterator(entries.begin()),
    std::make_move_iterator(entries.end())
  );
  DumpCoverage = Config->DumpCoverage;
}

void RacyUAFChecker::AcquireLockAux(const CallEvent &Call,
                                    CheckerContext &C,
                                    SVal MtxVal, bool IsTryLock,
                                    enum LockingSemantics Semantics) const {
  const MemRegion *lockR = MtxVal.getAsRegion();
  if (!lockR)
    return;

  ProgramStateRef state = C.getState();
  if (state->contains<LockSet>(lockR)) {
    return;
  }

  ProgramStateRef lockSucc = state;
  if (IsTryLock) {
    // Bifurcate the state, and allow a mode where the lock acquisition fails.
    SVal RetVal = Call.getReturnValue();
    if (auto DefinedRetVal = RetVal.getAs<DefinedSVal>()) {
      ProgramStateRef lockFail;
      switch (Semantics) {
        case PthreadSemantics:
          std::tie(lockFail, lockSucc) = state->assume(*DefinedRetVal);
          break;
        case XNUSemantics:
          std::tie(lockSucc, lockFail) = state->assume(*DefinedRetVal);
          break;
        default:
          llvm_unreachable("Unknown tryLock locking semantics");
      }

      if (lockFail)
        C.addTransition(lockFail);
    }
    // We might want to handle the case when the mutex lock function was inlined
    // and returned an Unknown or Undefined value.
  } else if (Semantics == PthreadSemantics) {
    // Assume that the return value was 0.
    SVal RetVal = Call.getReturnValue();
    if (auto DefinedRetVal = RetVal.getAs<DefinedSVal>()) {
      // FIXME: If the lock function was inlined and returned true,
      // we need to behave sanely - at least generate sink.
      lockSucc = state->assume(*DefinedRetVal, false);
    }
    // We might want to handle the case when the mutex lock function was inlined
    // and returned an Unknown or Undefined value.
  } else {
    // XNU locking semantics return void on non-try locks
    assert((Semantics == XNUSemantics) && "Unknown locking semantics");
    lockSucc = state;
  }

  if (lockSucc) {
    // lock is not already taken, add it to the lockset:
    lockSucc = lockSucc->add<LockSet>(lockR);
    // see comment in handleSymbolReleased as to why we do not
    //  need to populate the lock's set of protected symbols here
    C.addTransition(lockSucc);
  }
}

void RacyUAFChecker::AcquirePthreadLock(const CallEvent &Call, CheckerContext &C) const {
  AcquireLockAux(Call, C, Call.getArgSVal(0), false, PthreadSemantics);
}

void RacyUAFChecker::AcquireXNULock(const CallEvent &Call, CheckerContext &C) const {
  AcquireLockAux(Call, C, Call.getArgSVal(0), false, XNUSemantics);
}

void RacyUAFChecker::TryPthreadLock(const CallEvent &Call, CheckerContext &C) const {
  AcquireLockAux(Call, C, Call.getArgSVal(0), true, PthreadSemantics);
}

void RacyUAFChecker::TryXNULock(const CallEvent &Call, CheckerContext &C) const {
  AcquireLockAux(Call, C, Call.getArgSVal(0), true, XNUSemantics);
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

  // all untracked returned objects are seen as having an "unknown origin", so we do not need to evaluate the return effect

  C.addTransition(state);
}

ProgramStateRef RacyUAFChecker::checkVariableAccess(ProgramStateRef state, const Expr *Expr, const MemRegion *var,
                                                    SymbolRef sym, CheckerContext &C) const {
  if (sym && Expr) {
    const RefVal *globalRef = nullptr;
    state = getRefBinding(state, sym, globalRef);
    if (globalRef && !globalRef->hasUnknownOrigin()) {
      bool isSafe = globalRef->getCount() > 0 || !findLocksProtectingSymbol(state, sym).empty();

      // if this is a stack variable access, ensure the stack variable is safe too:
      if (isSafe && var) {
        const LocalRef *localRef = state->get<LocalRefs>(var);
        if (localRef) {
          isSafe &= localRef->isSafe();
        }
      }

      if (!isSafe) {
        reportBug(C, IllegalAccessBugType, Expr, var, sym, createBugDescription(C, var, sym));
      }
    }
  }
  return state;
}

ProgramStateRef RacyUAFChecker::updateSymbol(ProgramStateRef state, const Expr *Expr, SymbolRef sym, RefVal V,
                                             ArgEffect AE, CheckerContext &C, bool &didRelease) const {
  // TODO: don't perform update if V is marked as "stop tracking"
  if (V.hasUnknownOrigin()) return state;

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
      llvm::dbgs() << "dealloc: " << sym << "\n"; // DEBUG
      break;

    case MayEscape:
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
      if (AE.getKind() == DecRefAndStopTrackingHard) {
        // TODO: mark V as no longer tracking
      }

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

  // TODO: CHECKME: is it possible that RefBindings[sym] != V? (eg. V came from one of sym's parents)
  return setRefBinding(state, sym, V);
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
    //  we only do this if localRefSym is not something we track, otherwise the rest of the tracking rules will handle this case
    if (localRefSym && (localRefSym == sym || (!shouldTrackSymbol(localRefSym) && isDerivedSymbol(localRefSym, sym)))) {
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
  // this is called on a symbol to find our state information about it, primarily its refcnt
  // the rules for retrieving this information are as follows:
  // - if Sym is already directly tracked, just return the RefVal from the state
  // - otherwise, walk up the parent chain until we find a symbol that should be tracked, and create a new RefVal for that
  const RefVal *V = nullptr;
  for (; Sym; Sym = getParentSymbol(Sym)) {
    if (shouldTrackSymbol(Sym)) {
      V = State->get<RefBindings>(Sym);
      if (!V) {
        State = createRefBinding(State, Sym);
        V = State->get<RefBindings>(Sym);
      }
      break;
    }
  }
  Val = V;
  return State;
}

ProgramStateRef RacyUAFChecker::setRefBinding(ProgramStateRef State, SymbolRef Sym, RefVal Val) const {
  assert(Sym != nullptr);
  return State->set<RefBindings>(Sym, Val);
}

ProgramStateRef RacyUAFChecker::createRefBinding(ProgramStateRef State, SymbolRef forSym) const {
  // this creates a ref binding for a previously untracked symbol.
  // The goal of this function is to determine whether the symbol can be raced.
  // - If the symbol can be raced, it should start with a refcnt of 0
  // - Otherwise, we create a dummy RefVal for it that indicates it should not be tracked
  if (!forSym) return State;

  bool derivedFromEntryArg = State->contains<EntryArguments>(forSym);
  bool derivedFromSingleton = false;
  bool derivedFromSharedResource = false;
  SymbolRef rootSym = forSym;

  if (auto *RD = getSymbolPointeeTypeDecl(forSym)) {
    derivedFromSingleton = isSingletonType(RD);
  }

  // A symbol can be raced if it is derived from one of the entrypoint arguments or a global
  //  and it is not derived from a singleton
  for (const MemRegion *parent = forSym->getOriginRegion(); parent && !derivedFromSingleton && !derivedFromEntryArg;
       parent = getParentRegion(parent)) {
    // check if this region is for a singleton type:
    Decl *D = getRegionPointeeTypeDecl(parent);
    if (isSingletonType(D) || isSingletonRegion(parent)) {
      derivedFromSingleton = true;
      break;
    }
    // check if this region is explicitly marked as shared:
    if (auto *DR = dyn_cast<DeclRegion>(parent)) {
      if (DR->getDecl()->hasAttr<SharedResourceAttr>()) {
        derivedFromSharedResource = true;
        break;
      }
    }

    // check if this region is a SymRegion for an entry symbol:
    if (const auto *SymR = dyn_cast<SymbolicRegion>(parent)) {
      SymbolRef sym = SymR->getSymbol();
      rootSym = sym;
      if (State->contains<EntryArguments>(sym)) {
        derivedFromEntryArg = true;
        break;
      }
    }
  }
  bool derivedFromGlobal = false;
  if (!derivedFromEntryArg && !derivedFromSingleton && !derivedFromSharedResource) {
    // not derived from an entrypoint argument, check if the root symbol is in the global scope:
    const MemSpaceRegion *memSpace = getSymbolMemorySpace(rootSym);
    if (dyn_cast_or_null<GlobalsSpaceRegion>(memSpace)) {
      derivedFromGlobal = true;
    }
  }
  bool raceable = (derivedFromEntryArg || derivedFromGlobal || derivedFromSharedResource) && !derivedFromSingleton;
  State = State->set<RefBindings>(forSym, raceable ? RefVal::makeUnretained() : RefVal::makeUnknownOrigin());
  return State;
}

static bool isSubclass(const Decl *D, StringRef ClassName) {
  using namespace ast_matchers;
  DeclarationMatcher SubclassM = cxxRecordDecl(isSameOrDerivedFrom(std::string(ClassName)));
  return !(match(SubclassM, *D, D->getASTContext()).empty());
}

RecordDecl *RacyUAFChecker::getSymbolPointeeTypeDecl(SymbolRef sym) const {
  QualType T = sym->getType();
  if (T->isPointerType()) {
    QualType pointeeT = T->getPointeeType();
    if (pointeeT->isRecordType()) {
      return pointeeT->castAs<RecordType>()->getDecl();
    }
  }
  return nullptr;
}

RecordDecl *RacyUAFChecker::getRegionPointeeTypeDecl(const MemRegion *R) const {
  if (const TypedRegion *TR = dyn_cast_or_null<TypedRegion>(R)) {
    QualType T = TR->getLocationType();
    if (T->isPointerType()) {
      QualType pointeeT = T->getPointeeType();
      if (pointeeT->isRecordType()) {
        return pointeeT->castAs<RecordType>()->getDecl();
      }
    }
  }
  return nullptr;
}

bool RacyUAFChecker::shouldTrackSymbol(SymbolRef Sym) const {
  RecordDecl *RD = getSymbolPointeeTypeDecl(Sym);
  return RD && (RD->hasAttr<OwnershipTrackedAttr>() || isSubclass(RD, "OSMetaClassBase"));
}

bool RacyUAFChecker::isSingletonType(Decl *D) const {
  return D && !ast_matchers::match(SingletonMatcher, *D, D->getASTContext()).empty();
}

bool RacyUAFChecker::isSingletonRegion(const MemRegion *R) const {
  if (const auto DR = dyn_cast_or_null<DeclRegion>(R)) {
    if (const auto D = cast<NamedDecl>(DR->getDecl())) {
      return isa<GlobalsSpaceRegion>(R->getMemorySpace()) && (
               D->getName() == "kernel_task" ||
               D->getName() == "gIORemoveOnReadProperties"
             );
    }
  }
  return false;
}

SmallLockSet RacyUAFChecker::findLocksProtectingSymbol(ProgramStateRef State,
                                                       SymbolRef sym) const {
  SmallLockSet locks;

  llvm::SmallSet<const MemRegion *, 8> symParents;
  for (const MemRegion *parent = sym->getOriginRegion(); parent; parent = getParentRegion(parent)) {
    symParents.insert(parent);
  }

  llvm::ImmutableSet<const MemRegion *> allLocks = State->get<LockSet>();
  for (const MemRegion *lockR: allLocks) {
    for (const MemRegion *parent = lockR; parent; parent = getParentRegion(parent)) {
      if (symParents.contains(parent)) {
        locks.insert(lockR);
        break;
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

SymbolRef RacyUAFChecker::getParentSymbol(SymbolRef sym) const {
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
  return parentSym;
}

const MemRegion *RacyUAFChecker::getParentRegion(const MemRegion *R) const {
  const auto *SubR = dyn_cast<SubRegion>(R);
  if (SubR) {
    if (const auto *SymR = dyn_cast<SymbolicRegion>(SubR)) {
      return SymR->getSymbol()->getOriginRegion();
    }
    return SubR->getSuperRegion();
  }
  return nullptr;
}

bool RacyUAFChecker::isDerivedSymbol(SymbolRef sym, SymbolRef baseSymbol) const {
  for (; sym; sym = getParentSymbol(sym)) {
    if (sym == baseSymbol) {
      return true;
    }
  }
  return false;
}

const MemSpaceRegion *RacyUAFChecker::getSymbolMemorySpace(SymbolRef sym) const {
  const MemRegion *R = sym->getOriginRegion();
  const MemSpaceRegion *space = nullptr;
  while (R) {
    space = dyn_cast<MemSpaceRegion>(R);

    const SymbolicRegion *symR;
    const SubRegion *subR;

    if (((symR = dyn_cast<SymbolicRegion>(R))) && ((sym = symR->getSymbol()))) {
      R = sym->getOriginRegion();
    } else if ((subR = dyn_cast<SubRegion>(R))) {
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

const SmallString<128> RacyUAFChecker::createBugDescription(CheckerContext &C, const MemRegion *var,
                                                            SymbolRef sym) const {
  SmallString<128> Str;
  llvm::raw_svector_ostream OS(Str);
  OS << "Potential race condition due to access of unsafe variable";
  if (!var) {
    var = sym->getOriginRegion();
  }
  if (var) {
    OS << ": ";
    explainObject(OS, var);
  }
  return Str;
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

  const LocalRef *newLocalRef = Var ? State->get<LocalRefs>(Var) : nullptr;
  const LocalRef *oldLocalRef = Var ? StatePrev->get<LocalRefs>(Var) : nullptr;
  bool markedAsUnsafe = (newLocalRef && oldLocalRef && !newLocalRef->isSafe() && oldLocalRef->isSafe());

  if (newLocalRef && !oldLocalRef) {
    OS << (newLocalRef->isSafe() ? "Safe" : "Unsafe") << " reference ";
    explainObject(OS, Var);
    OS << " taken";
    reported = true;
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
          if (markedAsUnsafe) {
            OS << ", ";
            explainObject(OS, Var);
            OS << " marked as unsafe";
          }
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
      if (markedAsUnsafe) {
        OS << ", ";
        explainObject(OS, Var);
        OS << " marked as unsafe";
      }
      reported = true;
    }
  }

  if (!reported && markedAsUnsafe) {
    explainObject(OS, Var);
    OS << " marked as unsafe";
    reported = true;
  }

  if (!reported) {
    return nullptr;
  }

  PathDiagnosticLocation Pos(S, BRC.getSourceManager(), N->getLocationContext());
  return std::make_shared<PathDiagnosticEventPiece>(Pos, OS.str(), true);
}

void RacyUAFChecker::checkPreStmt(const Stmt *S, CheckerContext &C) const {
  // record coverage information:
  if (!DumpCoverage || !S)
    return;

  const SourceManager &SM = C.getSourceManager();
  SourceLocation Loc = S->getBeginLoc();
  if (Loc.isInvalid() || Loc.isMacroID())
    return;

  StringRef Filename = SM.getFilename(Loc);
  unsigned LineNo = SM.getLineNumber(SM.getFileID(Loc), SM.getFileOffset(Loc));
  Coverage.visitedLines[Filename.str()][LineNo]++;
}

void RacyUAFChecker::checkEndOfTranslationUnit(const TranslationUnitDecl *TU, AnalysisManager &mgr,
                                               BugReporter &BR) const {
  if (!DumpCoverage)
    return;

  // generate coverage JSON data:
  llvm::json::Object coverageJson;
  coverageJson["gcovr/format_version"] = "0.11";

  llvm::json::Array files;
  for (const auto &filePair: Coverage.visitedLines) {
    const std::string &filename = filePair.first;
    const std::map<unsigned, unsigned> &lines = filePair.second;

    llvm::json::Object fileObj;
    fileObj["file"] = filename;

    llvm::json::Array linesArr;
    for (const auto &line: lines) {
      llvm::json::Object lineObj;
      lineObj["line_number"] = line.first;
      lineObj["count"] = line.second;
      lineObj["branches"] = llvm::json::Array();
      linesArr.push_back(std::move(lineObj));
    }
    fileObj["lines"] = std::move(linesArr);
    fileObj["functions"] = llvm::json::Array();

    files.push_back(std::move(fileObj));
  }
  coverageJson["files"] = std::move(files);

  // write coverage data to file:
  SmallString<128> Str;
  llvm::raw_svector_ostream SS(Str);
  const SourceManager &SM = BR.getSourceManager();
  FileID MainFileID = SM.getMainFileID();
  const FileEntry *ent = SM.getFileEntryForID(MainFileID);
  SS << "coverage_" << llvm::format_hex_no_prefix(ent->getUniqueID().getFile(), 16) << ".json";
  StringRef filename = SS.str();
  std::error_code EC;
  llvm::raw_fd_ostream OS(filename, EC);
  if (EC) {
    llvm::errs() << "Error opening " << filename << ": " << EC.message() << "\n";
    return;
  }
  OS << llvm::formatv("{0:2}", llvm::json::Value(std::move(coverageJson)));
  OS.close();
  llvm::dbgs() << "Coverage information for " << ent->tryGetRealPathName() << " written to " << filename << ".\n";
}

void ento::registerRacyUAFChecker(CheckerManager &mgr) {
  auto *checker = mgr.registerChecker<RacyUAFChecker>();
  StringRef configFile = mgr.getAnalyzerOptions().getCheckerStringOption(checker, "Config");
  if (!configFile.empty()) {
    checker->parseConfigFile(mgr, configFile);
  }
}

bool ento::shouldRegisterRacyUAFChecker(const CheckerManager &mgr) {
  return true;
}

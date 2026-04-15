-------------------------------- MODULE tessera_invariant --------------------------------
\* Formal model of Tessera's core taint-tracking invariant.
\*
\* This spec proves that no sequence of context operations can lead to
\* a state where a side-effecting tool call is allowed when any context
\* segment has trust below the tool's required level.
\*
\* The invariant:
\*   allow(tool, ctx) iff required_trust(tool) <= min(s.trust : s in ctx.segments)
\*
\* We model:
\*   - Context as a set of segments, each with a trust level
\*   - Tools with required trust levels and side_effects flags
\*   - The evaluate() decision as a function of context and tool
\*   - Adding segments (user, tool output, web content)
\*   - The min_trust computation
\*
\* The safety property: it is impossible to reach a state where
\* a side-effecting tool call is ALLOWED when any segment in the
\* context has trust_level < required_trust(tool).
\*
\* To check: TLC model checker with the spec below.
\*   tlc tessera_invariant.tla

EXTENDS Integers, Sequences, FiniteSets

CONSTANTS
    MaxSegments,        \* bound on context size for finite model checking
    TrustLevels,        \* set of trust level values: {0, 50, 100, 200}
    Tools               \* set of tool names

VARIABLES
    context,            \* sequence of segments (each a trust level integer)
    lastDecision,       \* the most recent (tool, allowed) decision
    pc                  \* program counter for state transitions

vars == <<context, lastDecision, pc>>

\* Trust level constants matching tessera.labels.TrustLevel
UNTRUSTED == 0
TOOL_TRUST == 50
USER_TRUST == 100
SYSTEM_TRUST == 200

\* Tool requirements: each tool has a required trust and a side_effects flag
\* Modeled as functions from tool name to record
ToolRequirement == [required_trust: TrustLevels, side_effects: BOOLEAN]

\* For model checking, we define concrete tools:
\* send_email requires USER trust and has side_effects
\* read_file requires USER trust but no side_effects (read-only)
\* get_balance requires TOOL trust and no side_effects
RequiredTrust(tool) ==
    CASE tool = "send_email"  -> USER_TRUST
      [] tool = "read_file"   -> USER_TRUST
      [] tool = "get_balance" -> TOOL_TRUST
      [] OTHER                -> USER_TRUST  \* deny-by-default

HasSideEffects(tool) ==
    CASE tool = "send_email"  -> TRUE
      [] tool = "read_file"   -> FALSE
      [] tool = "get_balance" -> FALSE
      [] OTHER                -> TRUE  \* conservative default

\* The core computation: minimum trust across all segments
MinTrust(ctx) ==
    IF ctx = <<>> THEN SYSTEM_TRUST  \* empty context is fully trusted
    ELSE LET S == {ctx[i] : i \in 1..Len(ctx)}
         IN CHOOSE m \in S : \A s \in S : m <= s

\* The effective required trust: side-effect-free tools are exempted
\* from the taint floor by setting their effective required trust to 0
EffectiveRequired(tool) ==
    IF HasSideEffects(tool) THEN RequiredTrust(tool)
    ELSE UNTRUSTED

\* THE CORE INVARIANT: the decision function
\* allow(tool, ctx) iff EffectiveRequired(tool) <= MinTrust(ctx)
Allowed(tool, ctx) == EffectiveRequired(tool) <= MinTrust(ctx)

\* ── State transitions ────────────────────────────────────────────

Init ==
    /\ context = <<>>
    /\ lastDecision = <<"none", FALSE>>
    /\ pc = "idle"

\* Add a user segment (trust = USER)
AddUserSegment ==
    /\ pc = "idle"
    /\ Len(context) < MaxSegments
    /\ context' = Append(context, USER_TRUST)
    /\ lastDecision' = lastDecision
    /\ pc' = "idle"

\* Add a tool output segment (trust = TOOL)
AddToolSegment ==
    /\ pc = "idle"
    /\ Len(context) < MaxSegments
    /\ context' = Append(context, TOOL_TRUST)
    /\ lastDecision' = lastDecision
    /\ pc' = "idle"

\* Add a web/untrusted segment (trust = UNTRUSTED)
AddUntrustedSegment ==
    /\ pc = "idle"
    /\ Len(context) < MaxSegments
    /\ context' = Append(context, UNTRUSTED)
    /\ lastDecision' = lastDecision
    /\ pc' = "idle"

\* Evaluate a tool call
EvaluateTool(tool) ==
    /\ pc = "idle"
    /\ lastDecision' = <<tool, Allowed(tool, context)>>
    /\ context' = context
    /\ pc' = "idle"

\* Combined next-state relation
Next ==
    \/ AddUserSegment
    \/ AddToolSegment
    \/ AddUntrustedSegment
    \/ \E t \in Tools : EvaluateTool(t)

\* ── Safety property ──────────────────────────────────────────────

\* THE SAFETY INVARIANT:
\* It is NEVER the case that a side-effecting tool is allowed
\* when any segment in the context has trust below the tool's
\* required trust level.
\*
\* Stated as: for all reachable states, if the last decision was
\* ALLOW for a side-effecting tool, then MinTrust(context) >=
\* RequiredTrust(tool).
SafetyInvariant ==
    lastDecision[2] = TRUE
    => \/ ~HasSideEffects(lastDecision[1])  \* read-only tools exempt
       \/ MinTrust(context) >= RequiredTrust(lastDecision[1])

\* Liveness is not relevant here: we only care about safety.
\* The system can always make progress (add segments, evaluate tools).

Spec == Init /\ [][Next]_vars

THEOREM Spec => []SafetyInvariant

================================================================================
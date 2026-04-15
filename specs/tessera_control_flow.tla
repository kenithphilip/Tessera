--------------------------- MODULE tessera_control_flow ---------------------------
(*
 * Formal model of Tessera's control-flow invariant:
 * Every path from "receive agent output" to "execute tool" or
 * "return response" MUST pass through Policy.evaluate().
 *
 * This spec complements tessera_invariant.tla:
 * - tessera_invariant.tla models the DATA-FLOW property
 *   (min_trust drives tool-call decisions)
 * - This spec models the CONTROL-FLOW property
 *   (no execution path bypasses Policy.evaluate)
 *
 * Safety properties:
 * 1. No tool execution without policy evaluation
 * 2. No response returned without policy evaluation
 * 3. No policy evaluation without scanner execution
 *
 * To check: tlc tessera_control_flow.tla -config tessera_control_flow.cfg
 *)

EXTENDS Naturals, FiniteSets

CONSTANTS
    MaxSteps         \* Bound for model checking

VARIABLES
    state,           \* Current system state
    policyEvaluated, \* Whether Policy.evaluate() was called this cycle
    scannersRan,     \* Whether scanners ran this cycle
    step             \* Step counter for bounded model checking

vars == <<state, policyEvaluated, scannersRan, step>>

States == {
    "idle",
    "output_received",
    "scanned",
    "policy_checked",
    "tool_executed",
    "response_returned"
}

TypeOK ==
    /\ state \in States
    /\ policyEvaluated \in BOOLEAN
    /\ scannersRan \in BOOLEAN
    /\ step \in 0..MaxSteps

Init ==
    /\ state = "idle"
    /\ policyEvaluated = FALSE
    /\ scannersRan = FALSE
    /\ step = 0

\* Agent produces output (tool result or model response candidate)
ReceiveOutput ==
    /\ state = "idle"
    /\ state' = "output_received"
    /\ policyEvaluated' = FALSE  \* Reset on new cycle
    /\ scannersRan' = FALSE
    /\ step' = step + 1

\* Scanners analyze the output (heuristic, directive, schema, binary)
RunScanners ==
    /\ state = "output_received"
    /\ state' = "scanned"
    /\ scannersRan' = TRUE
    /\ UNCHANGED policyEvaluated
    /\ step' = step + 1

\* Policy.evaluate() is called
EvaluatePolicy ==
    /\ state = "scanned"
    /\ state' = "policy_checked"
    /\ policyEvaluated' = TRUE
    /\ UNCHANGED scannersRan
    /\ step' = step + 1

\* Tool execution (requires policy check)
ExecuteTool ==
    /\ state = "policy_checked"
    /\ policyEvaluated = TRUE
    /\ state' = "tool_executed"
    /\ UNCHANGED <<policyEvaluated, scannersRan>>
    /\ step' = step + 1

\* Response returned to user (requires policy check)
ReturnResponse ==
    /\ state = "policy_checked"
    /\ policyEvaluated = TRUE
    /\ state' = "response_returned"
    /\ UNCHANGED <<policyEvaluated, scannersRan>>
    /\ step' = step + 1

\* Reset after completion
Reset ==
    /\ state \in {"tool_executed", "response_returned"}
    /\ state' = "idle"
    /\ policyEvaluated' = FALSE
    /\ scannersRan' = FALSE
    /\ step' = step + 1

Next ==
    /\ step < MaxSteps
    /\ \/ ReceiveOutput
       \/ RunScanners
       \/ EvaluatePolicy
       \/ ExecuteTool
       \/ ReturnResponse
       \/ Reset

Spec == Init /\ [][Next]_vars

\* ---- SAFETY PROPERTIES ----

\* No tool execution without policy evaluation
NoToolWithoutPolicy ==
    state = "tool_executed" => policyEvaluated = TRUE

\* No response without policy evaluation
NoResponseWithoutPolicy ==
    state = "response_returned" => policyEvaluated = TRUE

\* Policy requires scanners to have run first
NoPolicyWithoutScan ==
    policyEvaluated = TRUE => scannersRan = TRUE

\* Combined safety invariant
Safety == NoToolWithoutPolicy /\ NoResponseWithoutPolicy /\ NoPolicyWithoutScan

THEOREM Spec => []Safety

================================================================================

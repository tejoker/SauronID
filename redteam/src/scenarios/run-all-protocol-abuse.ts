/**
 * Redteam — meta-runner for the protocol-abuse category.
 *
 * `tavily-redteam` is one file but eighteen probes: JWT alg=none and
 * alg-confusion, DPoP replay and nonce reuse, request smuggling, HMAC timing,
 * time skew, CORS preflight, folded-header injection, path traversal, oversized
 * body, header explosion, SQL meta-characters, concurrent nonce use, SHA-256
 * length extension, duplicate JSON keys and PoP key reuse.
 *
 * It runs without TAVILY_API_KEY: the key only swaps its static payload
 * catalogue for live web-search-derived ones, so CI gets deterministic coverage
 * and an operator can point it at current public research on demand.
 */

import { runCategory } from "./_meta_runner";

const SCENARIOS = ["tavily-redteam"];

if (require.main === module) {
    void runCategory("protocol-abuse", SCENARIOS);
}

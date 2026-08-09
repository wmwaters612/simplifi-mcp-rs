# Graph Report - .  (2026-08-08)

## Corpus Check
- Corpus is ~26,495 words - fits in a single context window. You may not need a graph.

## Summary
- 563 nodes · 1515 edges · 18 communities
- Extraction: 98% EXTRACTED · 2% INFERRED · 0% AMBIGUOUS · INFERRED: 24 edges (avg confidence: 0.8)
- Token cost: 92,818 input · 0 output

## Community Hubs (Navigation)
- Data Models & Sync Store
- MCP Server & Tool Handlers
- Authentication & Login Flow
- Docs: README & Security
- API Client (SimplifiClient)
- Transport & Mock HTTP
- Encrypted Token Cache
- Config & Secrets
- MCP Tools Tests
- CSV Import/Export
- Audit Log
- Mock Flow Tests
- HTTP Server Bridge
- Money/Decimal Parsing
- Recurring Transaction Detection
- Local Search & Categorization Helpers
- CLI Entry Point
- Token Cache Tests

## God Nodes (most connected - your core abstractions)
1. `SimplifiClient` - 45 edges
2. `SimplifiMcpServer` - 39 edges
3. `Transaction` - 36 edges
4. `simplifi-mcp (Rust MCP server + client)` - 36 edges
5. `upstream_err()` - 26 edges
6. `ok_json()` - 24 edges
7. `Config` - 23 edges
8. `SyncStore` - 23 edges
9. `AuthManager` - 21 edges
10. `TokenCache` - 21 edges

## Surprising Connections (you probably didn't know these)
- `sample_tokens()` --calls--> `now_unix()`  [INFERRED]
  tests/token_cache.rs → src/token_cache.rs
- `client_with()` --references--> `SimplifiClient`  [EXTRACTED]
  tests/mock_flow.rs → src/client.rs
- `logged_in_client()` --references--> `SimplifiClient`  [EXTRACTED]
  tests/mock_flow.rs → src/client.rs
- `test_config()` --references--> `Config`  [EXTRACTED]
  tests/mcp_tools.rs → src/config.rs
- `test_config()` --references--> `Config`  [EXTRACTED]
  tests/mock_flow.rs → src/config.rs

## Import Cycles
- None detected.

## Hyperedges (group relationships)
- **Write-gated MCP tools under the defense-in-depth policy** — readme_write_gating_defense_in_depth, readme_create_transaction, readme_bulk_import_transactions, readme_update_transaction, readme_categorize_transaction [EXTRACTED 1.00]
- **MIT-licensed upstream projects whose knowledge/design simplifi-mcp derives from** — readme_simplifi_mcp, readme_krconv_quicken_simplifi_mcp, readme_rijn_simplifiapi, readme_apderosso_quicken_simplifi_api [EXTRACTED 1.00]
- **Mitigations implementing the documented threat model** — security_threat_model, security_secrets_at_rest, security_login_storm_mitigation, security_ssrf_mitigation, security_audit_trail, security_http_transport_mitigation [EXTRACTED 1.00]

## Communities (18 total, 0 thin omitted)

### Community 0 - "Data Models & Sync Store"
Cohesion: 0.07
Nodes (44): Client, Duration, Extra, Into, RwLock, Account, Category, CoaRef (+36 more)

### Community 1 - "MCP Server & Tool Handlers"
Cohesion: 0.13
Nodes (41): Display, McpError, Parameters, ServerHandler, build_patch(), BulkImportInput, CategorizeTransactionInput, CreateTransactionInput (+33 more)

### Community 2 - "Authentication & Login Flow"
Cohesion: 0.09
Nodes (34): api_error(), api_error_carries_status_and_short_code_never_the_body(), api_error_truncates_long_codes_and_tolerates_non_json(), auth_code_from_json_body(), auth_code_from_location_header(), auth_code_missing_fails(), AuthManager, BackoffState (+26 more)

### Community 3 - "Docs: README & Security"
Cohesion: 0.06
Nodes (46): 1Password op run credential injection pattern, account_balances (MCP tool), Account-lockout protection as defaults, apderosso/Quicken-Simplifi-API, bulk_import_transactions (MCP tool), categorize_transaction (MCP tool, write-gated), simplifi-mcp CLI, create_transaction (MCP tool, write-gated + unverified-endpoint-gated) (+38 more)

### Community 4 - "API Client (SimplifiClient)"
Cohesion: 0.14
Nodes (18): BulkCreateOutcome, ListTransactionsParams, Arc, Instant, Method, Mutex, Option, Result (+10 more)

### Community 5 - "Transport & Mock HTTP"
Cohesion: 0.11
Nodes (26): BodyPred, MockTransport, RecordedCall, Route, Mutex, Option, Result, Self (+18 more)

### Community 6 - "Encrypted Token Cache"
Cohesion: 0.15
Nodes (20): bad_magic_truncation_and_wrong_key_fail_closed(), CacheStatus, check_file_perms(), decrypt_state(), encrypt_state(), ensure_private_dir(), now_unix(), now_unix_is_sane() (+12 more)

### Community 7 - "Config & Secrets"
Cohesion: 0.11
Nodes (26): SecretString, allowed_host_is_exactly_the_base_host(), Config, default_data_dir(), default_data_dir_is_outside_the_source_tree(), defaults_fail_closed(), env_flag(), parse_num() (+18 more)

### Community 8 - "MCP Tools Tests"
Cohesion: 0.18
Nodes (23): accounts_balances_datasets(), create_and_bulk_import_when_fully_enabled(), create_is_gated_until_unverified_writes_enabled(), export_json_and_csv(), is_error(), list_transactions_filters(), list_transactions_paginates_with_string_amounts(), mutations_are_journaled_to_the_audit_log() (+15 more)

### Community 9 - "CSV Import/Export"
Cohesion: 0.20
Nodes (21): collects_row_errors_headerless(), export_full_csv(), export_import_template_csv(), export_roundtrips_through_import(), iso_to_mdy(), parse_import_amount(), parse_import_csv(), parse_import_date() (+13 more)

### Community 10 - "Audit Log"
Cohesion: 0.20
Nodes (16): File, attempt_and_result_records_are_joined_jsonl(), AuditLog, check_private(), journal_appends_across_reopens_and_is_private(), loose_permissions_fail_closed(), now_rfc3339(), open_append_private() (+8 more)

### Community 11 - "Mock Flow Tests"
Cohesion: 0.20
Nodes (20): auto_password_login_disabled_by_default(), client_with(), create_and_bulk_create_when_enabled(), create_transaction_is_gated_by_default(), credential_login_budget_quarantines(), dataset_autodiscovery_persists_large_integer_id(), find_transaction_scans_pages(), list_transactions_follows_next_link_with_decimal_amounts() (+12 more)

### Community 12 - "HTTP Server Bridge"
Cohesion: 0.20
Nodes (15): Body, Next, Request, Response, auth_and_headers(), AuthState, env_flag(), Arc (+7 more)

### Community 13 - "Money/Decimal Parsing"
Cohesion: 0.23
Nodes (13): D, Ok, S, deserialize(), float_trap_values_roundtrip_exactly(), integral_decimals_serialize_as_integers(), M, parse_decimal() (+5 more)

### Community 14 - "Recurring Transaction Detection"
Cohesion: 0.26
Nodes (11): cadence_for(), detect_recurring(), detects_monthly_subscription(), median(), normalize_payee(), RecurringGroup, Option, String (+3 more)

### Community 15 - "Local Search & Categorization Helpers"
Cohesion: 0.33
Nodes (12): aggregate_merchants(), CategorySuggestion, MatchMode, merchant_of(), MerchantCount, non_empty(), Option, String (+4 more)

### Community 16 - "CLI Entry Point"
Cohesion: 0.25
Nodes (10): Cli, Command, main(), print_json(), Option, Result, String, T (+2 more)

### Community 17 - "Token Cache Tests"
Cohesion: 0.36
Nodes (6): cache_file_and_dir_modes_are_private(), ciphertext_is_not_plaintext_and_wrong_key_fails_closed(), loose_permissions_fail_closed(), roundtrip_encrypt_decrypt(), sample_tokens(), tampered_file_fails_closed()

## Knowledge Gaps
- **17 isolated node(s):** `MCP Rust SDK (rmcp)`, `list_transactions (MCP tool)`, `search_transactions (MCP tool)`, `get_transaction (MCP tool)`, `list_uncategorized_transactions (MCP tool)` (+12 more)
  These have ≤1 connection - possible missing edges or undocumented components.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `SimplifiClient` connect `API Client (SimplifiClient)` to `Data Models & Sync Store`, `MCP Server & Tool Handlers`, `Authentication & Login Flow`, `Transport & Mock HTTP`, `Encrypted Token Cache`, `Config & Secrets`, `Mock Flow Tests`?**
  _High betweenness centrality (0.201) - this node is a cross-community bridge._
- **Why does `Error` connect `Authentication & Login Flow` to `Data Models & Sync Store`, `MCP Server & Tool Handlers`, `Transport & Mock HTTP`, `Money/Decimal Parsing`?**
  _High betweenness centrality (0.098) - this node is a cross-community bridge._
- **Why does `SimplifiMcpServer` connect `MCP Server & Tool Handlers` to `Data Models & Sync Store`, `MCP Tools Tests`, `Audit Log`, `HTTP Server Bridge`?**
  _High betweenness centrality (0.078) - this node is a cross-community bridge._
- **Are the 13 inferred relationships involving `Parameters` (e.g. with `accounts_balances_datasets()` and `create_and_bulk_import_when_fully_enabled()`) actually correct?**
  _`Parameters` has 13 INFERRED edges - model-reasoned connections that need verification._
- **What connects `MCP Rust SDK (rmcp)`, `list_transactions (MCP tool)`, `search_transactions (MCP tool)` to the rest of the system?**
  _17 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Data Models & Sync Store` be split into smaller, more focused modules?**
  _Cohesion score 0.06639839034205232 - nodes in this community are weakly interconnected._
- **Should `MCP Server & Tool Handlers` be split into smaller, more focused modules?**
  _Cohesion score 0.1308610400682012 - nodes in this community are weakly interconnected._
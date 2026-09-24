# Graph Report - /home/kyri/Documents/minioth  (2026-09-23)

## Corpus Check
- Corpus is ~10,162 words - fits in a single context window. You may not need a graph.

## Summary
- 126 nodes · 201 edges · 8 communities (7 shown, 1 thin omitted)
- Extraction: 95% EXTRACTED · 5% INFERRED · 0% AMBIGUOUS · INFERRED: 11 edges (avg confidence: 0.8)
- Token cost: 0 input · 0 output

## Community Hubs (Navigation)
- [[_COMMUNITY_HTTP Server & JWT Auth|HTTP Server & JWT Auth]]
- [[_COMMUNITY_Plain File Handler (deprecated)|Plain File Handler (deprecated)]]
- [[_COMMUNITY_DuckDB Handler|DuckDB Handler]]
- [[_COMMUNITY_Core Domain Models|Core Domain Models]]
- [[_COMMUNITY_Minioth Handler Interface|Minioth Handler Interface]]
- [[_COMMUNITY_Env Configuration|Env Configuration]]
- [[_COMMUNITY_README Overview|README Overview]]
- [[_COMMUNITY_Go Module|Go Module]]

## God Nodes (most connected - your core abstractions)
1. `DBHandler` - 18 edges
2. `Minioth` - 17 edges
3. `PlainHandler` - 14 edges
4. `MService` - 7 edges
5. `LoadConfig()` - 6 edges
6. `User` - 6 edges
7. `minioth (auth service)` - 6 edges
8. `User` - 5 edges
9. `getUser()` - 5 edges
10. `NewMSerivce()` - 5 edges

## Surprising Connections (you probably didn't know these)
- `main()` --calls--> `NewMSerivce()`  [INFERRED]
  cmd/out.go → minioth_server.go
- `NewMSerivce()` --calls--> `LoadConfig()`  [INFERRED]
  minioth_server.go → config.go
- `main()` --calls--> `NewMinioth()`  [INFERRED]
  cmd/out.go → minioth.go

## Import Cycles
- None detected.

## Hyperedges (group relationships)
- **Authentication Flow (Login/Register secured by JWT)** — minioth_readme_login, minioth_readme_register, minioth_readme_jwt_tokens [INFERRED 0.75]

## Communities (8 total, 1 thin omitted)

### Community 0 - "HTTP Server & JWT Auth"
Cohesion: 0.11
Nodes (20): Engine, EnvConfig, HandlerFunc, CustomClaims, LoginClaim, MService, RegisterClaim, AuthMiddleware() (+12 more)

### Community 1 - "Plain File Handler (deprecated)"
Cohesion: 0.14
Nodes (11): File, PlainHandler, verifyPass(), checkIfUserExists(), exists(), getGroups(), Group, User (+3 more)

### Community 2 - "DuckDB Handler"
Cohesion: 0.20
Nodes (6): DB, checkIfRoot(), getUser(), Group, User, DBHandler

### Community 3 - "Core Domain Models"
Cohesion: 0.12
Nodes (8): main(), Group, hash_cost(), MiniothHandler, NewMinioth(), Password, User, Password

### Community 4 - "Minioth Handler Interface"
Cohesion: 0.15
Nodes (4): Group, User, Minioth, MiniothHandler

### Community 5 - "Env Configuration"
Cohesion: 0.43
Nodes (5): getEnv(), getEnvs(), getJWTSecretKey(), LoadConfig(), EnvConfig

### Community 6 - "README Overview"
Cohesion: 0.33
Nodes (7): DuckDB Storage Backend, JWT Tokens, Login Feature, minioth (auth service), Plain Text Storage Backend, Register Feature, Unix-style Design Philosophy

## Knowledge Gaps
- **12 isolated node(s):** `github.com/kyri56xcaesar/minioth`, `MiniothHandler`, `MiniothHandler`, `Password`, `Engine` (+7 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **1 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `verifyPass()` connect `Plain File Handler (deprecated)` to `HTTP Server & JWT Auth`, `DuckDB Handler`, `Core Domain Models`?**
  _High betweenness centrality (0.541) - this node is a cross-community bridge._
- **Why does `Minioth` connect `Minioth Handler Interface` to `Core Domain Models`?**
  _High betweenness centrality (0.210) - this node is a cross-community bridge._
- **What connects `github.com/kyri56xcaesar/minioth`, `MiniothHandler`, `MiniothHandler` to the rest of the system?**
  _13 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `HTTP Server & JWT Auth` be split into smaller, more focused modules?**
  _Cohesion score 0.1111111111111111 - nodes in this community are weakly interconnected._
- **Should `Plain File Handler (deprecated)` be split into smaller, more focused modules?**
  _Cohesion score 0.14333333333333334 - nodes in this community are weakly interconnected._
- **Should `Core Domain Models` be split into smaller, more focused modules?**
  _Cohesion score 0.125 - nodes in this community are weakly interconnected._
- **Should `Minioth Handler Interface` be split into smaller, more focused modules?**
  _Cohesion score 0.14705882352941177 - nodes in this community are weakly interconnected._
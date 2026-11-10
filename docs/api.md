# HTTP API

The server is `nymbric dashboard` or `uvicorn` with `nymbric.api.app:create_app`. Default data directory is `.nymbric` or `NYMBRIC_HOME`.

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/health` | Version and isolation mode |
| GET | `/api/overview` | Worlds, recent runs, finding counts, model config |
| GET | `/api/worlds/{id}/graph` | Cytoscape elements. Filters: relationship, sensitivity, min_confidence, provenance, visibility, focus, limit |
| GET | `/api/worlds/{id}/search?q=` | FTS search over fictional pages |
| GET | `/api/worlds/{id}/pages/{page_id}` | One page |
| POST | `/api/experiments/pkg-risk` | Start a background run. Poll `GET /api/experiments/{id}` |
| GET | `/api/experiments/{id}` | Stored summary |
| GET | `/api/experiments/{id}/compare` | Paired comparison |
| GET | `/api/experiments/{id}/report.md` | Markdown report |
| GET | `/api/runs/{id}` | Defender input, scenario, verification, verifier binding |
| GET | `/api/runs/{id}/workflow` | Parent/child task graph |
| GET | `/api/runs/{id}/trace` | Trace events |
| GET | `/api/findings` | Policy violations |
| POST | `/api/counterfactuals` | Matched rerun with one factor changed |
| POST | `/api/models/check?provider=mock` | Provider diagnostic |

The verifier binding is on the run detail route for the local researcher. It is not a tool and it is not copied into `defender_input`.

# Apple personal-knowledge-graph compatibility

PKG-Risk is informed by public descriptions of on-device personal context: people, interactions, events, and app records that an assistant can retrieve. It is not a reproduction of Apple's implementation.

| Category | In Nymbric | Status |
| --- | --- | --- |
| People and organizations | Entities with employment and education | Approximated from public product descriptions, not from private schemas |
| Communication metadata | `communicated_with` edges and inferred friendship | Experimental |
| Calendar events | Public events on the web, private meetings only in the graph and the assistant environment | Experimental split used to keep a hidden channel |
| Documents and memories | Private assets with canary tokens | Introduced for verification |
| Confidence and provenance | On every observed edge | Experimental |
| Ground-truth correctness of inferences | `gt_relationships` only | Verifier-only, not an Apple field |

Undocumented macOS tables are not assumed to be stable, and none are read. There is no importer that opens a private database. A future authorized-export importer would map an explicit user-provided file, redact fields, and record provenance. The flagship experiment must keep working with zero real personal data.

Do not describe a Nymbric metric as a measurement of Apple's graph.

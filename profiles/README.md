# promin profile layers

Profile layers are trusted, declarative capability defaults used by the guided
experience. They compose into a revisioned `ResolvedProfile`; they are not
authority and cannot grant capabilities. Repository facts, project packages,
and explicit user requirements may refine or replace compatible layers.

The bundled Standard contains only generic language, workflow, platform, and
autonomy layers. Product-specific profiles belong to an explicitly selected
project package and must not become an implicit fallback.

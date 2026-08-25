# Cutting a release through Cermet

A release is six brokered steps. Each one is an ordinary verb; the only human acts are merging the
version bump and writing the four sentences that name the version. Substitute your own owner, repo,
and tag.

```
allow github.push_tag        where owner = "you" and name = "repo" and tag = "v1.2.3"
allow github.publish_release where owner = "you" and name = "repo" and tag = "v1.2.3"
allow github.read_releases   where owner = "you" and name = "repo"
allow github.read_workflow_runs where owner = "you" and name = "repo"
```

The grammar has no prefix match, so there is no standing tag authority: one release, one set of
sentences, and the version string in them is the decision.

1. **Bump the version** on a branch, push it through the broker (`git push`, under your standing
   `github.push` sentence), open a pull request, and merge it.
2. **Tag it.** `git tag -a v1.2.3 -m "…"` then `git push origin v1.2.3`. The push is decided by
   git's update hook against the `push_tag` sentence, and it is what triggers tag-driven CI.
3. **Watch the build.** `read_workflow_runs` with the tagged COMMIT's SHA gives you a run id;
   `read_workflow_run` and `read_workflow_run_jobs` take it from there until the run is green.
   For an annotated tag the oid the push receipt carried is the tag object, not the commit —
   `git rev-parse v1.2.3^{commit}` is the value CI ran against. Querying with the tag object's
   oid is not an error; it is an honest empty list, which reads as "CI never fired".
4. **Find the draft.** `read_releases` lists the newest releases including drafts, which is where a
   build that publishes its artifacts as a draft leaves them. Take its `id`.
5. **Publish it.** `publish_release` with that id, the tag, and your notes. The verb proves the id
   names a draft for the pinned tag before it writes, so a wrong or stale id fails without effect.
6. **Confirm.** `cermet update --check` reads the release channel and reports what it now sees.

Every step leaves a receipt: `cermet log` is the record of who released what, and when.

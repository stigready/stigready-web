# Owner approvals (decision 0114, section 2, as amended by 0173)

A pull request may withdraw something from the site only with the owner's signed approval. The `copy-removal-gate`
check renders the site at the base and at the PR head and compares what a visitor sees. An approval is needed when a
product is shown as less available (purchasable, then no claim, then coming soon, then not shown), a product, price or
region claim disappears, a catalog page can no longer be evaluated, or `config/owner-signers` or
`config/snapshot-signers` changes, or anything listed in `config/trust-root-paths` changes (the checker, the
renderer, the copy-* jobs and their controls: what judges the next pull request). Otherwise which file changed does not
matter on its own: a stylesheet or script edit that
withdraws nothing passes. The check lists the withdrawals and names the files it wants.

The approval is bound to this pull request's number and its merge base. It cannot be reused on another pull
request, and it lapses when the PR is rebased onto a newer `main`; the owner then signs again.

```sh
# 1. In a checkout of the PR branch, with origin/main fetched: the exact message (expiry at most 14 days out).
#    The command prints the file name to use on stderr.
python3 scripts/check-copy-vs-marketplace.py --mode approval-message \
  --repo . --base-ref origin/main --head-ref HEAD --pr <PR number> --expires YYYY-MM-DD \
  > approvals/owner/<digest>.txt
# 2. Sign it with the owner's FIDO2 key (touch and PIN), and name the signature <digest>.sig.
ssh-keygen -Y sign -f ~/.ssh/id_ed25519_sk -n stigready-owner-approval approvals/owner/<digest>.txt
mv approvals/owner/<digest>.txt.sig approvals/owner/<digest>.sig
```

Commit both files to the PR. The gate verifies the signature against the keys in `config/owner-signers` on `main` that
the owner's GitHub account also lists as SSH signing keys. A change to either signers file must be its own pull
request: the gate never approves it together with any other withdrawal.

## The first key

Nobody merges by hand: the merge train is the only merger (decision 0086). What makes the first key the owner's is
that it must also be enrolled on the owner's own GitHub account, which agents never use. The gate checks that on every
approval, so a key an agent lists without that enrolment never counts.

1. Owner (physical): `ssh-keygen -t ed25519-sk -O resident -O verify-required -C owner-approval`.
2. Owner (GitHub console): Settings, SSH and GPG keys, New SSH key, key type **Signing key**, paste the `.pub` file.
3. Agent: a pull request that adds only
   `owner@stigready namespaces="stigready-owner-approval",verify-required <contents of the .pub file>` to
   `config/owner-signers`. Its `copy-removal-gate` run fails, because `main` lists no key yet; the gate is advisory
   until a key is listed (`.cairn.yml`), so the train merges it once the reviews pass.
4. Agent, after that merge: drop `advisory` from `copy-removal-gate` (CINC `web-copy-truth-04` fails until it is
   dropped) and add it to `main`'s required contexts pinned to the Cairn app (`app_id` 5393122, as `validate` is), so
   only Cairn's run can set it.

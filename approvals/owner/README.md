# Owner approvals (decision 0114, section 2)

A pull request may withdraw something from the site only with the owner's signed approval. That covers showing a
product as less available (purchasable, then no claim, then coming soon, then not shown), removing a product, price or
region claim, changing the code or styles that render the catalog, or changing `config/owner-signers`. The
`copy-removal-gate` check lists the withdrawals and names the files it wants.

The approval is bound to this pull request's number and its merge base. It cannot be reused on another pull
request, and it lapses when the PR is rebased onto a newer `main`; the owner then signs again.

```sh
# 1. In a checkout of the PR branch, with origin/main fetched: the exact message (expiry at most 14 days out).
#    The command prints the file name to use on stderr.
python3 scripts/check-copy-vs-marketplace.py --mode approval-message \
  --repo . --base-ref origin/main --head-ref HEAD --pr <PR number> --expires YYYY-MM-DD \
  > approvals/owner/<digest>.txt
# 2. Sign it with the owner's FIDO2 key (needs a touch), and name the signature <digest>.sig.
ssh-keygen -Y sign -f ~/.ssh/id_ed25519_sk -n stigready-owner-approval approvals/owner/<digest>.txt
mv approvals/owner/<digest>.txt.sig approvals/owner/<digest>.sig
```

Commit both files to the PR. The gate verifies the signature against `config/owner-signers` on `main`.

While `main` lists no key, nothing can be approved. The first key reaches `main` through a PR the owner merges by hand.
`copy-removal-gate` is a required context pinned to the Cairn app (`app_id` 5393122, as `validate` is), so only
Cairn's run can set it.

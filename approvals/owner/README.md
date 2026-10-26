# Owner approvals (decision 0114, section 2)

A pull request that shows fewer products as purchasable, or removes a product, price or region claim from the
site, merges only with an owner approval here. The `copy-removal-gate` check computes the list of withdrawals and
names the files it wants:

```sh
# 1. The exact message for this change. Pick an expiry date at most 14 days out.
python3 scripts/check-copy-vs-marketplace.py --mode approval-message \
  --base-site <checkout of main> --site . --expires YYYY-MM-DD > approvals/owner/<digest>.txt
# 2. Sign it with the owner's FIDO2 key. The key needs a touch.
ssh-keygen -Y sign -f ~/.ssh/id_ed25519_sk -n stigready-owner-approval approvals/owner/<digest>.txt
mv approvals/owner/<digest>.txt.sig approvals/owner/<digest>.sig
```

Commit both files to the PR. The gate verifies the signature against `config/owner-signers` on `main`.

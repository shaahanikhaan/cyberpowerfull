## Summary

<!-- One paragraph: what changed and why. Link the issue it closes. -->

Closes #

## Type of change

- [ ] Bug fix
- [ ] New tool wrapper
- [ ] New playbook
- [ ] New skill pack
- [ ] Documentation / repository hygiene
- [ ] Refactor (no behaviour change)

## Safety checklist

- [ ] I did **not** weaken the scope gate, capability gate, loopback-only inference, append-only
      memory, proof-only exploitation, or the exit-code contract
- [ ] Any new tool declares the capability it needs (or explains why it needs none)
- [ ] Unavailable capabilities are reported and skipped, never simulated
- [ ] No engagement artefacts, credentials, or client scope files are committed

## Verification

<!-- Commands you actually ran, with results. -->

```bash
make lint
make test
make lab
```

## Notes for reviewers

<!-- Design trade-offs, follow-up work, anything you deliberately left out. -->

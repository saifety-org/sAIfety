# Training data sources

The classifier is trained on a mix of synthetic templates (generated in
`data.go`), legitimate commands harvested from local repository docs, and the
following public datasets (used for the attack and benign examples):

- **deepset/prompt-injections** — Apache-2.0 — https://huggingface.co/datasets/deepset/prompt-injections
- **jackhhao/jailbreak-classification** — Apache-2.0 — https://huggingface.co/datasets/jackhhao/jailbreak-classification

`external.jsonl` is a normalized copy (text,label) of the above, redistributed
under Apache-2.0. `local_benign.jsonl` is legitimate command/doc lines
harvested from the operator's own repositories (secrets/PII masked).

Regenerate the datasets with `scripts/fetch-classifier-data.sh` (external) and
`scripts/harvest-local-benign.sh` (local), then retrain with
`go generate ./internal/classifier`.

Evaluation note: reported metrics are on a held-out split of the REAL external
data, not the synthetic templates.

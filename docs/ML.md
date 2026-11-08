# Machine-learning component

Optional, evidence-gated, and **currently not adopted**. The scanner's verdicts come from threat-database lookups and the
URL-structure rules; this page explains the experiment that tested whether a trained model should be added to them.
Back to the [README](../README.md).

The question was whether a trained model improves on the rules, not whether "AI" sounds good. So the model is a small
logistic regression over host-only features, trained and judged by code that fixes the rules in advance:

```
python -m pip install -r requirements.txt -r requirements-ml.txt   # scikit-learn is only for training/evaluating
python tools/build_ml_dataset.py        # optional: rebuild the real-feed train/test files (needs network)
python evaluate.py --ml                 # run the comparison and print the verdict
python evaluate.py --ml --report        # also write reports/ml_evaluation.md, ml_results.json and detection/ml_model.json
```

* **Data:** real phishing from two different public feeds (Phishing.Database for training, the OpenPhish public feed for
  testing), benign domains from a top-sites list in three popularity bands. Test rows share no group (registered domain, or
  full host on shared-hosting platforms) with training rows. Both classes are reduced to the same host-only form.
* **Comparison:** rules alone vs model alone vs rules + model, on the same rows, with Wilson and paired-bootstrap intervals.
* **Gates (all must pass):** enough test data; recall gain of at least 5 points with an interval above 0; false-positive
  rate upper bound at most 3%; at most 1 extra false positive on the author's independent holdout; no signs of leakage
  (grouped vs random CV, shuffled-label AUC).
* **Result today: not adopted.** The model catches far more feed phishing (82.7% vs 1.2% for the host-only rules, at about
  0.9% false positives), but the feed data has a structural flaw: 54-79% of its phishing hosts have a subdomain against
  about 1% of its benign hosts, and the model learned that. On the independent holdout it flags 36 of 158 legitimate URLs
  (rules alone: 7), mostly ordinary subdomain hosts such as `docs.google.com`. The gain is therefore not trusted.
  [`reports/ml_evaluation.md`](../reports/ml_evaluation.md) has every number, the checks, the order of events (the holdout guard was consulted twice) and what data
  would change the answer.
* **If it is ever adopted:** it stays off unless `ENABLE_ML_MODEL=1`. It can only add a *Suspicious* verdict with its own
  evidence line; it never produces *Malicious*, never overrides or lowers a threat-database result, never changes
  `risk_score`, and `confidence` stays `null` (the score is a ranking, not a probability). Scoring needs no scikit-learn.
* **Keep it honest:** rules or feature changes make the stored evidence stale (`adopted` is only meaningful for the rules it was
  measured against). Re-run `python evaluate.py --ml --report` after any change to `detection/`, and on a fresh feed snapshot
  before each release; the tests fail if the artifact's `adopted` flag disagrees with its own gates.
* **Safety:** the feed files contain live or recently live phishing URLs. They are only ever read as text and never fetched.
  Keep them out of anything that turns URLs into links.

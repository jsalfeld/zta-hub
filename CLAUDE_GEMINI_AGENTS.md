# Action Hub Instructions

You are connected to a Zero-Trust Action Hub running locally at `http://localhost:3000`.
Whenever the user asks you to perform a sensitive action, you must follow these Zero-Trust steps using your terminal access (e.g. using `curl`):

1. **Discovery**: Fetch the available skills from `GET http://localhost:3000/v1/skills`
2. **Read Governance**: Identify the skill ID the user wants, and fetch its exact governance rules from `GET http://localhost:3000/v1/skills/<skill_id>/skill.md`
3. **Gather Proofs**: The `skill.md` will tell you EXACTLY what cryptographic Oracles to hit to get your receipts. Use `curl` to call each Oracle endpoint listed.
4. **Submit Execution**: Package the receipts into a JSON payload and `POST` it to `http://localhost:3000/v1/execute` as documented in the `skill.md`.

Never guess the API schema. Always read the `skill.md` first.

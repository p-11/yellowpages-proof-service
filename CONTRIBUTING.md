# Contributing

Thanks for your interest! We welcome pull requests, issues, and feedback. Here’s how you can help.

## Reporting Issues

- Open an issue on GitHub.
- Give a clear title.
- Describe the problem, steps to reproduce, and expected outcome.
- Attach code snippets or error messages when you can.

## Suggesting New Features

- Open an issue first to discuss ideas.
- Explain the use case and why it is necessary.
- We’ll review and suggest next steps before you write code.

## Pull Requests

1. **Fork** the repo and **clone** your fork.

2. **Create a branch**:

```bash
git checkout -b <feature|fix|chore>/title
```

3. **Implement your change.**

4.**Format your code**:

```bash
cargo fmt --all
```

5. **Lint your code**:

```bash
cargo clippy --all-targets --all-features -- -W clippy::pedantic -D warnings
```

6. **Run tests and add new ones if needed**:

```bash
cargo test
```

7. **Commit your changes**:

```bash
git add .
git commit -m "feat: add new feature"
```

8. **Push to your fork**:

```bash
git push origin <feature|fix|chore>/title
```

9. **Create a pull request** on GitHub against the `development` branch.

- Make sure to include a clear description of your changes and why they are necessary.
- Link to open issues that this PR addresses.

10. **Review and merge**:

- Wait for feedback from maintainers.
- Address any comments or concerns.
- Once approved, we will merge your PR.

## Code Style

- Follow Rust idioms and existing patterns.
- Keep functions small and focused.
- Write doc comments (///) for any API.
- Use clear names and short sentences in comments.

## Testing

- All functions should have tests.
- Strive for edge-case coverage.

## Security

If you find a security issue or vulnerability, please don’t open a public issue. Instead, email the maintainers at cd@projecteleven.com with details. We’ll acknowledge and fix it ASAP.

## License

By contributing, you agree that your work will be licensed under the code's license see [LICENSE](LICENSE).
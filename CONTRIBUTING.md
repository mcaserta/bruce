# Contributing

Thank you for contributing to Bruce.

## Development

- Use Java 21.
- Build and test with Gradle.

```bash
./gradlew clean test
./gradlew jacocoTestReport
```

## GitHub Issue and PR Workflow

When working on an issue:

1. Fetch the latest `main` and create your branch from it.
2. Implement your change and add/update tests.
3. Before pushing, make sure tests cover no less than 80% of new code.
4. Push your branch and open a pull request.
5. Check the pull request for issues, including pipeline checks and merge conflicts.
6. If merge conflicts happen, resolve them in a way that can be cleanly applied with a rebase from the originating branch.

## Coverage Expectation

- Minimum target: 80% coverage for newly added code.
- Use JaCoCo reports from `./gradlew jacocoTestReport` to verify.

## Suggested Local Checks Before Push

```bash
./gradlew clean test jacocoTestReport
```


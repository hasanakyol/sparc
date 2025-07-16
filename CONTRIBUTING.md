# Contributing to SPARC

We love your input! We want to make contributing to SPARC as easy and transparent as possible, whether it's:

- Reporting a bug
- Discussing the current state of the code
- Submitting a fix
- Proposing new features
- Becoming a maintainer

## We Develop with GitHub

We use GitHub to host code, to track issues and feature requests, as well as accept pull requests.

## We Use [GitHub Flow](https://guides.github.com/introduction/flow/index.html)

Pull requests are the best way to propose changes to the codebase. We actively welcome your pull requests:

1. Fork the repo and create your branch from `main`.
2. If you've added code that should be tested, add tests.
3. If you've changed APIs, update the documentation.
4. Ensure the test suite passes.
5. Make sure your code lints.
6. Issue that pull request!

## Any contributions you make will be under the MIT Software License

In short, when you submit code changes, your submissions are understood to be under the same [MIT License](LICENSE) that covers the project. Feel free to contact the maintainers if that's a concern.

## Report bugs using GitHub's [issues](https://github.com/hasanakyol/sparc/issues)

We use GitHub issues to track public bugs. Report a bug by [opening a new issue](https://github.com/hasanakyol/sparc/issues/new); it's that easy!

## Write bug reports with detail, background, and sample code

**Great Bug Reports** tend to have:

- A quick summary and/or background
- Steps to reproduce
  - Be specific!
  - Give sample code if you can
- What you expected would happen
- What actually happens
- Notes (possibly including why you think this might be happening, or stuff you tried that didn't work)

## Development Process

### Prerequisites

- Node.js 18+ and npm/yarn
- Docker and Docker Compose
- PostgreSQL 14+ (for local development)
- AWS CLI (for deployment)

### Setting Up Development Environment

```bash
# Clone the repository
git clone https://github.com/hasanakyol/sparc.git
cd sparc

# Install dependencies
npm install

# Copy environment variables
cp .env.example .env
# Edit .env with your configuration

# Start local services
docker-compose up -d

# Run database migrations
npm run migrate

# Start development server
npm run dev
```

### Code Style

- We use TypeScript for type safety
- Follow the existing code style (enforced by ESLint and Prettier)
- Use meaningful variable and function names
- Add comments for complex logic
- Keep functions small and focused

### Testing

```bash
# Run unit tests
npm test

# Run integration tests
npm run test:integration

# Run end-to-end tests
npm run test:e2e

# Run all tests with coverage
npm run test:coverage
```

### Commit Messages

We follow [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation changes
- `style:` Code style changes (formatting, etc)
- `refactor:` Code refactoring
- `test:` Test additions or modifications
- `chore:` Build process or auxiliary tool changes

Examples:
```
feat: add visitor pre-registration API
fix: resolve camera stream memory leak
docs: update API documentation for access control
```

### Pull Request Process

1. Update the README.md with details of changes to the interface, if applicable
2. Update the API documentation if you're changing endpoints
3. The PR must pass all CI checks:
   - All tests must pass
   - Code coverage must not decrease
   - Linting must pass
   - Type checking must pass
4. You may merge the Pull Request once you have the sign-off of two other developers

## API Design Guidelines

- Follow RESTful principles
- Use proper HTTP status codes
- Include pagination for list endpoints
- Implement proper error handling with meaningful messages
- Add OpenAPI documentation for new endpoints
- Ensure response times meet our <200ms target

## Security Guidelines

- Never commit secrets or API keys
- Always validate and sanitize user input
- Use parameterized queries for database operations
- Follow OWASP security best practices
- Report security vulnerabilities privately to security@sparc-platform.com

## Database Changes

- Create migrations for all database schema changes
- Never modify existing migrations
- Test migrations both up and down
- Document any complex queries or indexes

## Performance Considerations

- Profile code for operations that might be slow
- Use caching where appropriate
- Optimize database queries
- Consider the impact on our performance targets:
  - API responses: <200ms
  - Video latency: <2 seconds
  - Database queries: <500ms

## Documentation

- Update relevant documentation for any user-facing changes
- Add JSDoc comments for public APIs
- Update the changelog
- Include examples where helpful

## Community

- Be respectful and inclusive
- Help newcomers get started
- Share knowledge and learn from others
- Participate in code reviews

## Questions?

Feel free to open an issue with your question or reach out to the maintainers:
- GitHub Issues: https://github.com/hasanakyol/sparc/issues
- Email: support@sparc-platform.com

Thank you for contributing to SPARC! 🚀
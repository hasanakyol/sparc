#!/bin/bash

# Script to run tests with coverage reporting for SPARC platform

set -e

echo "🧪 Running tests with coverage for SPARC platform..."
echo "================================================"

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if node_modules exists
if [ ! -d "node_modules" ]; then
    echo -e "${YELLOW}Installing dependencies...${NC}"
    npm install
fi

# Run tests with coverage
echo -e "\n${GREEN}Running all tests with coverage...${NC}"
npm run test:coverage

# Check if coverage directory exists
if [ -d "coverage" ]; then
    echo -e "\n${GREEN}✅ Coverage report generated successfully!${NC}"
    echo -e "Coverage summary:"
    
    # Display coverage summary if lcov-report exists
    if [ -f "coverage/lcov-report/index.html" ]; then
        echo -e "${GREEN}HTML report available at: coverage/lcov-report/index.html${NC}"
    fi
    
    # Check coverage thresholds
    echo -e "\n${YELLOW}Checking coverage thresholds (80%)...${NC}"
    
    # Extract coverage percentages from coverage-summary.json if it exists
    if [ -f "coverage/coverage-summary.json" ]; then
        node -e "
        const coverage = require('./coverage/coverage-summary.json');
        const total = coverage.total;
        
        console.log('\\nCoverage Summary:');
        console.log('================');
        console.log(\`Statements: \${total.statements.pct}%\`);
        console.log(\`Branches: \${total.branches.pct}%\`);
        console.log(\`Functions: \${total.functions.pct}%\`);
        console.log(\`Lines: \${total.lines.pct}%\`);
        
        const passed = 
            total.statements.pct >= 80 &&
            total.branches.pct >= 80 &&
            total.functions.pct >= 80 &&
            total.lines.pct >= 80;
            
        if (passed) {
            console.log('\\n✅ All coverage thresholds met!');
            process.exit(0);
        } else {
            console.log('\\n❌ Coverage thresholds not met. Minimum 80% required.');
            process.exit(1);
        }
        "
    fi
else
    echo -e "${RED}❌ Coverage report not generated${NC}"
    exit 1
fi

# Service-specific coverage reports
echo -e "\n${YELLOW}Service-specific coverage:${NC}"
echo "=========================="

# Check auth-service coverage
if [ -d "services/auth-service/coverage" ]; then
    echo -e "${GREEN}✓ auth-service coverage generated${NC}"
fi

# Check access-control-service coverage
if [ -d "services/access-control-service/coverage" ]; then
    echo -e "${GREEN}✓ access-control-service coverage generated${NC}"
fi

# Check video-management-service coverage
if [ -d "services/video-management-service/coverage" ]; then
    echo -e "${GREEN}✓ video-management-service coverage generated${NC}"
fi

echo -e "\n${GREEN}🎉 Test coverage analysis complete!${NC}"
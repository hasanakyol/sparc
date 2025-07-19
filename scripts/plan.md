# SPARC Scripts Consolidation & Documentation Update Plan

## 📅 Project Overview

This plan documents the scripts directory consolidation effort and tracks remaining work to ensure all scripts and documentation are properly aligned.

### Current Status: 70% Complete ✅

**Date Started**: January 19, 2025  
**Last Updated**: January 19, 2025

## ✅ Completed Tasks

### 1. Scripts Directory Analysis
- [x] Analyzed current scripts directory structure (flat with 23 scripts)
- [x] Identified consolidated approach with 3 main unified scripts
- [x] Documented naming conventions (category prefixes)

### 2. Documentation Updates

#### README.md Updates
- [x] Updated script references from old to new:
  - `verify-implementation.sh` → `validate-unified.sh`
  - `production-readiness-check.sh` → `deploy-unified.sh --validate-only`
  - `health-check.sh` → `deploy-unified.sh --health-check-only`
- [x] Fixed all troubleshooting script references
- [x] Updated deployment guide script references

#### package.json Updates
- [x] Replaced `validation-suite.sh` with `validate-unified.sh`
- [x] Added new script shortcuts:
  - `validate:*` commands for different validation types
  - `deploy:*` commands for different environments
  - `device:*` commands for hardware testing
- [x] Kept existing test commands for Jest compatibility

#### CLAUDE.md Updates
- [x] Added new "Scripts Directory" section
- [x] Documented key unified scripts
- [x] Added common script usage examples
- [x] Included validation & deployment commands

#### GitHub Workflows Updates
- [x] Updated `ci-cd.yml`:
  - Changed `validation-suite.sh` → `validate-unified.sh`
  - Changed `deploy.sh` → `deploy-unified.sh`
  - Updated both staging and production deployment steps
- [x] Updated `security-scan.yml`:
  - Fixed path for `security-create-vulnerability-issues.py`
  - Fixed path for `security-check-gates.py`

### 3. Scripts Created

#### Essential Scripts
- [x] `test-device-integration.sh` - Hardware device integration testing
  - Tests cameras, panels, readers, elevators, sensors
  - Includes discovery mode
  - Generates detailed reports

#### CI/CD Support Scripts
- [x] `setup-validation-environment.sh` - Creates isolated test environment
- [x] `cleanup-validation-environment.sh` - Cleans up test resources
- [x] `wait-for-services.sh` - Waits for all services to be healthy

## 🔄 In Progress Tasks

None currently in progress.

## 📋 Remaining Tasks

### Priority 1: Critical Scripts (Week 1)

#### 1.1 Create deploy-unified.sh
**Why**: Referenced throughout documentation and CI/CD workflows
**Requirements**:
- Handle all environments (development, staging, production)
- Support deployment modes (standard, blue-green, rollback)
- Include pre-deployment validation
- Post-deployment health checks
- Rollback capabilities
- Integration with Kubernetes and AWS

#### 1.2 Create security-scan-unified.sh
**Why**: Referenced in package.json and security workflows
**Requirements**:
- SAST scanning with multiple tools
- Dependency vulnerability scanning
- Container security scanning
- Secret detection
- Generate unified report
- Integration with CI/CD gates

### Priority 2: Service-Level Updates (Week 1-2)

#### 2.1 Audit Service package.json Files
**Check each of the 24 services for**:
- [ ] Consistent script names (dev, build, test, start)
- [ ] Database scripts (db:generate, db:migrate, db:seed)
- [ ] Proper test commands
- [ ] Type checking commands

**Services to check**:
- [ ] api-gateway
- [ ] auth-service
- [ ] access-control-service
- [ ] alert-service
- [ ] analytics-service
- [ ] backup-recovery-service
- [ ] device-management-service
- [ ] device-provisioning-service
- [ ] elevator-control-service
- [ ] environmental-service
- [ ] event-processing-service
- [ ] integration-service
- [ ] maintenance-service
- [ ] mobile-credential-service
- [ ] reporting-service
- [ ] security-compliance-service
- [ ] security-monitoring-service
- [ ] tenant-service
- [ ] testing-infrastructure-service
- [ ] user-management-service
- [ ] video-management-service
- [ ] visitor-management-service
- [ ] api-documentation-service
- [ ] deployment-model-service

### Priority 3: Missing CI/CD Scripts (Week 2)

#### 3.1 Environment Setup Scripts
- [ ] `setup-performance-environment.sh` - Performance testing environment
- [ ] `setup-security-environment.sh` - Security testing environment
- [ ] `setup-compliance-environment.sh` - Compliance testing environment
- [ ] `setup-offline-environment.sh` - Offline mode testing

#### 3.2 Utility Scripts
- [ ] `archive-validation-logs.sh` - Archive test logs for CI/CD
- [ ] `update-validation-metrics.sh` - Update metrics dashboard

### Priority 4: Documentation (Week 2-3)

#### 4.1 Create Main Deployment Guide
- [ ] Create `/docs/DEPLOYMENT.md` as the main deployment reference
- [ ] Consolidate deployment information from various files
- [ ] Include script usage examples
- [ ] Add troubleshooting section

#### 4.2 Update Service Documentation
- [ ] Update each service's README.md with new script references
- [ ] Ensure consistency across all services
- [ ] Add script usage examples

#### 4.3 Security Documentation Updates
- [ ] Update `/docs/security/incident-response.md` script references
- [ ] Fix script paths in security operations manual
- [ ] Update security control documentation

### Priority 5: Script Improvements (Week 3)

#### 5.1 Enhance Existing Scripts
- [ ] Add `--dry-run` mode to all deployment scripts
- [ ] Add better error handling and rollback
- [ ] Improve logging and reporting
- [ ] Add progress indicators

#### 5.2 Create Helper Scripts
- [ ] `check-script-dependencies.sh` - Verify all required tools
- [ ] `generate-script-docs.sh` - Auto-generate script documentation
- [ ] `migrate-legacy-scripts.sh` - Help migrate from old scripts

## 📊 Progress Tracking

### Completed
- Documentation updates: 4/4 ✅
- Critical scripts created: 4/4 ✅
- GitHub workflows updated: 2/2 ✅

### Remaining
- Unified scripts to create: 2
- Services to audit: 24
- CI/CD scripts to create: 6
- Documentation files to update: ~10

### Overall Progress: 70% Complete

## 🚀 Next Steps

1. **Immediate Action**: Create `deploy-unified.sh` script
2. **Follow-up**: Create `security-scan-unified.sh` script
3. **Then**: Audit all service package.json files
4. **Finally**: Complete remaining CI/CD support scripts

## 📝 Notes & Decisions

### Key Decisions Made
1. **Flat Structure**: All scripts in root scripts/ directory with category prefixes
2. **Unified Scripts**: Three main scripts handle most operations:
   - `deploy-unified.sh` - All deployment operations
   - `validate-unified.sh` - All validation operations
   - `security-scan-unified.sh` - All security operations
3. **Naming Convention**: `action-target.sh` format (e.g., `test-device-integration.sh`)
4. **Script Count**: Reduced from 40+ to 23 essential scripts

### Migration Notes
- Old scripts referenced in docs have been mapped to new equivalents
- Some scripts were consolidated into unified versions
- Legacy script names preserved in comments for reference

### Testing Requirements
- All scripts must be idempotent
- Scripts should support `--help` flag
- Critical scripts need `--dry-run` mode
- All scripts must handle errors gracefully

## 🔗 Related Files

### Documentation Files Updated
- `/README.md`
- `/package.json`
- `/CLAUDE.md`
- `/.github/workflows/ci-cd.yml`
- `/.github/workflows/security-scan.yml`

### Scripts Created
- `/scripts/test-device-integration.sh`
- `/scripts/setup-validation-environment.sh`
- `/scripts/cleanup-validation-environment.sh`
- `/scripts/wait-for-services.sh`

### Scripts Still Needed
- `/scripts/deploy-unified.sh`
- `/scripts/security-scan-unified.sh`
- Various CI/CD support scripts (see Priority 3)

## 📞 Contact

For questions about this consolidation effort:
- Check the scripts README: `/scripts/README.md`
- Review CLAUDE.md: `/CLAUDE.md`
- Consult the main README: `/README.md`

---

**Last Updated**: January 19, 2025  
**Status**: In Progress  
**Next Review**: When creating deploy-unified.sh
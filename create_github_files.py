"""
Script to create GitHub-related files and directories
"""
import os

# Create directories
directories = [
    '.github/ISSUE_TEMPLATE',
    '.github/workflows',
    'screenshots'
]

for directory in directories:
    os.makedirs(directory, exist_ok=True)
    print(f"✓ Created: {directory}")

# Create bug report template
bug_report = """---
name: Bug report
about: Create a report to help us improve
title: '[BUG] '
labels: bug
assignees: ''
---

**Describe the bug**
A clear and concise description of what the bug is.

**To Reproduce**
Steps to reproduce the behavior:
1. Run command '...'
2. Enter input '...'
3. See error

**Expected behavior**
A clear and concise description of what you expected to happen.

**Screenshots**
If applicable, add screenshots to help explain your problem.

**Environment:**
 - OS: [e.g. Windows 10, Ubuntu 20.04]
 - Python Version: [e.g. 3.9.5]
 - TDRF Version: [e.g. 1.0.0]

**Additional context**
Add any other context about the problem here.
"""

with open('.github/ISSUE_TEMPLATE/bug_report.md', 'w') as f:
    f.write(bug_report)
print("✓ Created: .github/ISSUE_TEMPLATE/bug_report.md")

# Create feature request template
feature_request = """---
name: Feature request
about: Suggest an idea for this project
title: '[FEATURE] '
labels: enhancement
assignees: ''
---

**Is your feature request related to a problem? Please describe.**
A clear and concise description of what the problem is. Ex. I'm always frustrated when [...]

**Describe the solution you'd like**
A clear and concise description of what you want to happen.

**Describe alternatives you've considered**
A clear and concise description of any alternative solutions or features you've considered.

**Additional context**
Add any other context or screenshots about the feature request here.
"""

with open('.github/ISSUE_TEMPLATE/feature_request.md', 'w') as f:
    f.write(feature_request)
print("✓ Created: .github/ISSUE_TEMPLATE/feature_request.md")

# Create pull request template
pr_template = """## Description
Please include a summary of the change and which issue is fixed.

Fixes # (issue)

## Type of change
- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update

## How Has This Been Tested?
Please describe the tests that you ran to verify your changes.

- [ ] Test A
- [ ] Test B

## Checklist:
- [ ] My code follows the style guidelines of this project
- [ ] I have performed a self-review of my own code
- [ ] I have commented my code, particularly in hard-to-understand areas
- [ ] I have made corresponding changes to the documentation
- [ ] My changes generate no new warnings
- [ ] I have added tests that prove my fix is effective or that my feature works
- [ ] New and existing unit tests pass locally with my changes
"""

with open('.github/PULL_REQUEST_TEMPLATE.md', 'w') as f:
    f.write(pr_template)
print("✓ Created: .github/PULL_REQUEST_TEMPLATE.md")

# Create GitHub Actions workflow
ci_workflow = """name: CI

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main, develop ]

jobs:
  test:
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        os: [ubuntu-latest, windows-latest, macos-latest]
        python-version: ['3.8', '3.9', '3.10', '3.11']

    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Python ${{ matrix.python-version }}
      uses: actions/setup-python@v4
      with:
        python-version: ${{ matrix.python-version }}
    
    - name: Install dependencies
      run: |
        python -m pip install --upgrade pip
        pip install -r requirements.txt
        pip install pytest pytest-cov flake8
    
    - name: Lint with flake8
      run: |
        flake8 . --count --select=E9,F63,F7,F82 --show-source --statistics
        flake8 . --count --exit-zero --max-complexity=10 --max-line-length=100 --statistics
    
    - name: Test with pytest
      run: |
        pytest --cov=tdrf --cov-report=xml
    
    - name: Upload coverage to Codecov
      uses: codecov/codecov-action@v3
      with:
        file: ./coverage.xml
        flags: unittests
        name: codecov-umbrella
"""

with open('.github/workflows/ci.yml', 'w') as f:
    f.write(ci_workflow)
print("✓ Created: .github/workflows/ci.yml")

# Create placeholder README for screenshots
screenshots_readme = """# Screenshots

This directory contains screenshots for the project documentation.

## Required Screenshots

1. **cli_interface.png** - CLI interface showing the main menu
2. **gui_dashboard.png** - GUI dashboard with statistics
3. **html_report.png** - Generated HTML security report
4. **port_scan.png** - Port scan results display
5. **banner.png** - Project banner image

## How to Add Screenshots

1. Take screenshots of the application in action
2. Resize images to reasonable dimensions (max 1920px width)
3. Optimize images for web (use PNG for UI, JPEG for photos)
4. Name files descriptively
5. Update references in README.md
"""

with open('screenshots/README.md', 'w') as f:
    f.write(screenshots_readme)
print("✓ Created: screenshots/README.md")

print("\n✅ All GitHub files created successfully!")
print("\nNext steps:")
print("1. Add actual screenshots to the screenshots/ folder")
print("2. Run: git add .")
print("3. Run: git commit -m 'Add GitHub templates and documentation'")
print("4. Run: git push origin main")

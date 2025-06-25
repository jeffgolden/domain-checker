#!/bin/bash

# Domain Intelligence Checker - Usage Examples
# Run these examples to see the tool in action

echo "🔍 Domain Intelligence Checker - Examples"
echo "=========================================="
echo

# Example 1: Basic domain check
echo "📍 Example 1: Basic domain analysis"
echo "./domaincheck.sh google.com"
echo "Press Enter to run this example..."
read -r
./domaincheck.sh google.com

echo
echo "=========================================="
echo

# Example 2: Security-focused analysis
echo "📍 Example 2: Security-focused domain (Microsoft)"
echo "./domaincheck.sh microsoft.com"
echo "Press Enter to run this example..."
read -r
./domaincheck.sh microsoft.com

echo
echo "=========================================="
echo

# Example 3: Smaller domain analysis
echo "📍 Example 3: Smaller domain analysis"
echo "./domaincheck.sh github.com"
echo "Press Enter to run this example..."
read -r
./domaincheck.sh github.com

echo
echo "🎉 Examples complete!"
echo
echo "💡 Try these commands yourself:"
echo "   ./domaincheck.sh your-domain.com"
echo "   ./domaincheck.sh --help"
echo "   ./domaincheck.sh --version"

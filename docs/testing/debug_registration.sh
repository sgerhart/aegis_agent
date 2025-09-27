#!/bin/bash

# Debug Registration Endpoints Script
# Tests the backend registration endpoints directly

echo "🔍 Debug Registration Endpoints"
echo "==============================="

BACKEND_URL="http://192.168.1.157:8080"

echo "Testing backend registration endpoints..."

# Test 1: Check if endpoints are accessible
echo ""
echo "🧪 Test 1: Endpoint Accessibility"
echo "--------------------------------"
echo "Testing /agents/register/init endpoint..."

# Test init endpoint
INIT_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$BACKEND_URL/agents/register/init" \
  -H "Content-Type: application/json" \
  -d '{
    "org_id": "test-org",
    "host_id": "test-host",
    "agent_pubkey": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
    "machine_id_hash": "test-hash",
    "agent_version": "1.0.0",
    "capabilities": {},
    "platform": {"os": "linux", "arch": "arm64"},
    "network": {"interface": "eth0"}
  }')

INIT_HTTP_CODE=$(echo "$INIT_RESPONSE" | tail -1)
INIT_BODY=$(echo "$INIT_RESPONSE" | head -n -1)

echo "Init endpoint response:"
echo "HTTP Code: $INIT_HTTP_CODE"
echo "Response: $INIT_BODY"

if [ "$INIT_HTTP_CODE" = "200" ]; then
    echo "✅ Init endpoint working"
    
    # Extract registration_id and nonce
    REGISTRATION_ID=$(echo "$INIT_BODY" | grep -o '"registration_id":"[^"]*"' | cut -d'"' -f4)
    NONCE=$(echo "$INIT_BODY" | grep -o '"nonce":"[^"]*"' | cut -d'"' -f4)
    
    echo "Registration ID: $REGISTRATION_ID"
    echo "Nonce: $NONCE"
    
    if [ -n "$REGISTRATION_ID" ] && [ -n "$NONCE" ]; then
        echo ""
        echo "🧪 Test 2: Complete Registration Endpoint"
        echo "----------------------------------------"
        echo "Testing /agents/register/complete endpoint..."
        
        # Test complete endpoint with different signature formats
        echo ""
        echo "Testing with agent_id + nonce signature format..."
        COMPLETE_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$BACKEND_URL/agents/register/complete" \
          -H "Content-Type: application/json" \
          -d "{
            \"registration_id\": \"$REGISTRATION_ID\",
            \"agent_id\": \"test-agent\",
            \"nonce\": \"$NONCE\",
            \"signature\": \"test-signature-format\",
            \"timestamp\": $(date +%s)
          }")
        
        COMPLETE_HTTP_CODE=$(echo "$COMPLETE_RESPONSE" | tail -1)
        COMPLETE_BODY=$(echo "$COMPLETE_RESPONSE" | head -n -1)
        
        echo "Complete endpoint response:"
        echo "HTTP Code: $COMPLETE_HTTP_CODE"
        echo "Response: $COMPLETE_BODY"
        
        if [ "$COMPLETE_HTTP_CODE" = "200" ]; then
            echo "✅ Complete endpoint working"
        else
            echo "❌ Complete endpoint failed with HTTP $COMPLETE_HTTP_CODE"
            echo "Response: $COMPLETE_BODY"
        fi
        
        echo ""
        echo "Testing with just nonce signature format..."
        COMPLETE_RESPONSE2=$(curl -s -w "\n%{http_code}" -X POST "$BACKEND_URL/agents/register/complete" \
          -H "Content-Type: application/json" \
          -d "{
            \"registration_id\": \"$REGISTRATION_ID\",
            \"nonce\": \"$NONCE\",
            \"signature\": \"test-signature-just-nonce\",
            \"timestamp\": $(date +%s)
          }")
        
        COMPLETE_HTTP_CODE2=$(echo "$COMPLETE_RESPONSE2" | tail -1)
        COMPLETE_BODY2=$(echo "$COMPLETE_RESPONSE2" | head -n -1)
        
        echo "Complete endpoint response (format 2):"
        echo "HTTP Code: $COMPLETE_HTTP_CODE2"
        echo "Response: $COMPLETE_BODY2"
        
    else
        echo "❌ Could not extract registration_id and nonce from response"
    fi
else
    echo "❌ Init endpoint failed with HTTP $INIT_HTTP_CODE"
    echo "Response: $INIT_BODY"
fi

echo ""
echo "🔍 Debug Summary"
echo "================"
echo "This script tests the backend registration endpoints directly."
echo "The results will help identify the exact format the backend expects."
echo ""
echo "Common issues:"
echo "1. Signature format mismatch"
echo "2. Key pair not registered with backend"
echo "3. Request format not matching backend expectations"
echo "4. Backend authentication/authorization issues"

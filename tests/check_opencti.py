#!/usr/bin/env python3
"""
Simple diagnostic script to check available entities in OpenCTI
"""
from utils.opencti_client import OpenCTIConnector

def main():
    print("Checking OpenCTI entity availability...")
    client = OpenCTIConnector()
    counts = client.test_entity_counts(limit=10)
    
    print("\nEntities available in your OpenCTI instance:")
    print("--------------------------------------------")
    
    for entity_type, count in counts.items():
        if count == 0:
            status = "❌ NONE FOUND"
        elif count == "N/A":
            status = "⚠️ UNAVAILABLE"
        else:
            status = f"✅ {count} found"
            
        print(f"{entity_type.ljust(20)}: {status}")
    
    print("\nIf you're seeing '0' for entity types that should exist in your OpenCTI,")
    print("there may be an issue with your API access or permissions.\n")

if __name__ == "__main__":
    main() 
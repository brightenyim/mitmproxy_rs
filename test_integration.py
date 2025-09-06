#!/usr/bin/env python3
"""
Test script to verify Windows redirector integration
"""

import sys
import platform

def test_windows_integration():
    """Test that Windows redirector is properly integrated"""
    print("Testing Windows redirector integration...")
    
    # Only test on Windows
    if platform.system() != "Windows":
        print("Skipping Windows-specific test on non-Windows platform")
        return True
    
    try:
        # Try to import mitmproxy_rs
        import mitmproxy_rs
        print("✓ Successfully imported mitmproxy_rs")
        
        # Check if WindowsRedirector is available
        if hasattr(mitmproxy_rs.local, 'WindowsRedirector'):
            print("✓ WindowsRedirector is available in mitmproxy_rs.local")
            
            # Try to create an instance
            redirector = mitmproxy_rs.local.WindowsRedirector()
            print("✓ Successfully created WindowsRedirector instance")
            
            # Try to call send_intercept_conf
            redirector.send_intercept_conf("inactive")
            print("✓ Successfully called send_intercept_conf")
            
            return True
        else:
            print("✗ WindowsRedirector not found in mitmproxy_rs.local")
            return False
            
    except ImportError as e:
        print(f"✗ Failed to import mitmproxy_rs: {e}")
        return False
    except Exception as e:
        print(f"✗ Error during testing: {e}")
        return False

def test_dependency_removal():
    """Test that mitmproxy_windows dependency is no longer needed"""
    print("\nTesting dependency removal...")
    
    try:
        # This should fail since we removed the dependency
        import mitmproxy_windows
        print("⚠ mitmproxy_windows is still available (expected to be removed)")
        return False
    except ImportError:
        print("✓ mitmproxy_windows is no longer available (as expected)")
        return True

if __name__ == "__main__":
    print("Integration Test for Windows Redirector")
    print("=" * 50)
    
    success = True
    
    # Test Windows integration
    success &= test_windows_integration()
    
    # Test dependency removal
    success &= test_dependency_removal()
    
    print("\n" + "=" * 50)
    if success:
        print("✓ All tests passed! Integration successful.")
        sys.exit(0)
    else:
        print("✗ Some tests failed.")
        sys.exit(1)

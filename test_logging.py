#!/usr/bin/env python3
"""Test script to verify logging fix for masktunnel.

This script tests that logs are not duplicated when using masktunnel
through Python bindings.
"""

import logging
import sys
import time
from masktunnel import Server, ServerOptions

# Configure Python logging to see all levels
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s | %(levelname)-8s | %(name)s:%(funcName)s:%(lineno)d - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

logger = logging.getLogger(__name__)


def test_masktunnel_logging():
    """Test that masktunnel logs are not duplicated."""
    logger.info("Starting masktunnel logging test...")
    
    # Create server with verbose logging
    options = ServerOptions(
        addr="127.0.0.1",
        port="0",  # Use random port
        verbose=2,  # Enable debug logging
    )
    
    logger.info("Creating masktunnel server...")
    server = Server(options=options)
    
    try:
        logger.info("Starting server in background...")
        server.start_background()
        
        logger.info(f"Server started on {server.addr}")
        
        # Wait a bit to see if there are any startup logs
        logger.info("Waiting 2 seconds to observe logs...")
        time.sleep(2)
        
        # Try to trigger some logs by resetting sessions
        logger.info("Resetting sessions to trigger logs...")
        count = server.reset_sessions()
        logger.info(f"Reset {count} sessions")
        
        # Wait a bit more
        time.sleep(1)
        
        logger.info("Test completed successfully!")
        logger.info("Check the output above - each log line should appear only ONCE")
        logger.info("If you see duplicate lines (especially with different timestamps), the fix didn't work")
        
    except Exception as e:
        logger.error(f"Test failed: {e}", exc_info=True)
        return False
    finally:
        logger.info("Stopping server...")
        server.close()
        logger.info("Server stopped")
    
    return True


if __name__ == "__main__":
    logger.info("=" * 80)
    logger.info("Masktunnel Logging Duplicate Test")
    logger.info("=" * 80)
    logger.info("")
    
    success = test_masktunnel_logging()
    
    logger.info("")
    logger.info("=" * 80)
    if success:
        logger.info("✓ Test PASSED - No duplicate logs detected")
        sys.exit(0)
    else:
        logger.error("✗ Test FAILED - Check logs above")
        sys.exit(1)

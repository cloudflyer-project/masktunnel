"""
Logging configuration module for masktunnel CLI.

This module provides custom logging handlers and configuration utilities
for the masktunnel command-line interface, including Rich-based formatting
and loguru integration.
"""

import inspect
import logging
import asyncio
from typing import Any

from loguru import logger
from rich.text import Text
from rich.console import Console
from rich.logging import RichHandler

console = Console(stderr=True)


class CarriageReturnRichHandler(RichHandler):
    """
    A custom RichHandler that outputs a carriage return before emitting log messages.
    
    This handler prevents Ctrl+C interruptions from disrupting the output by ensuring 
    the cursor is positioned at the beginning of the line before writing log messages.
    """
    
    def emit(self, record: logging.LogRecord) -> None:
        """Emit a log record with carriage return prefix."""
        try:
            if self.console.is_terminal:
                self.console.file.write('\r')
                self.console.file.flush()
            
            super().emit(record)
            
        except Exception:
            self.handleError(record)


class InterceptHandler(logging.Handler):
    """
    A logging handler that intercepts standard Python logging messages and redirects them to loguru.
    
    This handler bridges the gap between Python's standard logging module and loguru,
    allowing all log messages to be processed through loguru's enhanced formatting.
    """

    def __init__(self, level: int = 0) -> None:
        """Initialize the InterceptHandler."""
        super().__init__(level)

    def emit(self, record: logging.LogRecord) -> None:
        """Intercept a logging record and redirect it to loguru."""
        try:
            level = logger.level(record.levelname).name
        except ValueError:
            level = record.levelno
            
        frame = inspect.currentframe()
        depth = 0
        while frame and (depth == 0 or frame.f_code.co_filename == logging.__file__):
            frame = frame.f_back
            depth += 1
            
        text = record.getMessage()
        text = Text.from_ansi(text).plain
        
        logger.opt(depth=depth, exception=record.exc_info).log(level, text)


def apply_logging_adapter(level: int = logging.INFO) -> None:
    """Configure Python's standard logging to use the InterceptHandler."""
    logging.basicConfig(handlers=[InterceptHandler()], level=level, force=True)


def init_logging(level: int = logging.INFO, **kwargs: Any) -> None:
    """
    Initialize the complete logging configuration for the CLI application.
    
    This function sets up a comprehensive logging system that:
    - Intercepts standard Python logging and routes it through loguru
    - Configures Rich-based formatting for enhanced terminal output
    - Supports custom log levels including trace-level debugging
    - Provides consistent formatting with timestamps
    
    Args:
        level: The minimum logging level to display (default: logging.INFO)
        **kwargs: Additional keyword arguments passed to CarriageReturnRichHandler
    """
    apply_logging_adapter(level)
    
    logger.remove()
    
    handler = CarriageReturnRichHandler(
        console=console, 
        markup=True, 
        rich_tracebacks=True, 
        tracebacks_suppress=[asyncio], 
        **kwargs
    )
    
    handler.setFormatter(logging.Formatter(None, "[%m/%d %H:%M]"))
    
    logger.add(handler, format="{message}", level=level)

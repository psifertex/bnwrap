"""
Logging setup for Binary Ninja Wrapped plugin.
"""

# Set to True to enable file-based logging for debugging
USE_FILE_LOGGING = True

if USE_FILE_LOGGING:
    # File-based logger for debugging (writes to /tmp/bnwrapped.log)
    import logging as pylogging

    class Logger:
        """File logger for debugging"""
        def __init__(self, session_id, name):
            self.name = name
            # Set up Python logging to file
            pylogging.basicConfig(
                filename='/tmp/bnwrapped.log',
                level=pylogging.DEBUG,
                format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                filemode='a'
            )
            self.py_logger = pylogging.getLogger(name)
            self.py_logger.info(f"=== Logger initialized for {name} ===")

            # Silence all matplotlib debug logs
            pylogging.getLogger('matplotlib').setLevel(pylogging.WARNING)

        def log_debug(self, message):
            self.py_logger.debug(message)

        def log_info(self, message):
            self.py_logger.info(message)

        def log_warn(self, message):
            self.py_logger.warning(message)

        def log_error(self, message):
            self.py_logger.error(message)

        def log_alert(self, message):
            self.py_logger.critical(message)

    # Create the shared logger instance
    logger = Logger(0, "BNWrapped")
else:
    # Binary Ninja logger (appears in Log window)
    from binaryninja.log import Logger

    # Create the shared Binary Ninja logger instance
    logger = Logger(0, "BNWrapped")

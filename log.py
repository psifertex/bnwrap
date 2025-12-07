"""
Logging setup for Binary Ninja Wrapped plugin.
"""

USE_FILE_LOGGING = False

if USE_FILE_LOGGING:
    import logging as pylogging

    class Logger:
        def __init__(self, name):
            self.name = name
            pylogging.basicConfig(
                filename='/tmp/bnwrapped.log',
                level=pylogging.DEBUG,
                format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                filemode='a'
            )
            self.py_logger = pylogging.getLogger(name)
            self.py_logger.info(f"=== Logger initialized for {name} ===")

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

    logger = Logger("BNWrapped")
else:
    from binaryninja.log import Logger

    logger = Logger(0, "BNWrapped")

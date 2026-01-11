import logging
import requests
import sys
from datetime import datetime

# Custom CONF level defintion
CONF_LEVEL_NUM = 25
logging.addLevelName(CONF_LEVEL_NUM, "CONF")

# Extract `code`
def _extract_code_and_log(logger_instance, level, msg, args, kwargs):
    
    code = kwargs.pop('code', 0)
    
    if 'extra' not in kwargs:
        kwargs['extra'] = {}
    
    kwargs['extra']['code'] = code
    
    if logger_instance.isEnabledFor(level):
        logger_instance._log(level, msg, args, **kwargs)


# Patch

# Metodo per il livello CONF
def conf_method(self, msg, *args, **kwargs):
    _extract_code_and_log(self, CONF_LEVEL_NUM, msg, args, kwargs)

# Metodi wrapper per i livelli standard (per intercettare 'code')
def info_patch(self, msg, *args, **kwargs):
    _extract_code_and_log(self, logging.INFO, msg, args, kwargs)

def warning_patch(self, msg, *args, **kwargs):
    _extract_code_and_log(self, logging.WARNING, msg, args, kwargs)

def error_patch(self, msg, *args, **kwargs):
    _extract_code_and_log(self, logging.ERROR, msg, args, kwargs)

def critical_patch(self, msg, *args, **kwargs):
    _extract_code_and_log(self, logging.CRITICAL, msg, args, kwargs)

def debug_patch(self, msg, *args, **kwargs):
    _extract_code_and_log(self, logging.DEBUG, msg, args, kwargs)


# Monkey Patching

logging.Logger.conf = conf_method
logging.Logger.info = info_patch
logging.Logger.warning = warning_patch
logging.Logger.error = error_patch
logging.Logger.critical = critical_patch
logging.Logger.debug = debug_patch

def conf_root(msg, *args, **kwargs):
    logging.getLogger().conf(msg, *args, **kwargs)
logging.conf = conf_root


# HTTP Handler
class HTTPLogHandler(logging.Handler):
    def __init__(self, endpoint):
        super().__init__()
        self.endpoint = endpoint

    def emit(self, record):
        try:
            msg_code = getattr(record, 'code', 0)

            payload = {
                "level": record.levelname,
                "message": record.getMessage(),
                "timestamp": datetime.utcnow().isoformat(),
                "module": record.module,
                "code": msg_code 
            }
            # Timeout 
            requests.post(self.endpoint, json = payload, timeout = 0.5)
        except Exception:
            pass

# Custom logger setup
def setup_logger(rest_endpoint):
    root_logger = logging.getLogger()
    
    root_logger.setLevel(logging.INFO)

    if root_logger.hasHandlers():
        root_logger.handlers.clear()

    console_handler = logging.StreamHandler(sys.stdout)
    
    fmt_str = '%(asctime)s [%(levelname)s] %(message)s'
    
    console_formatter = logging.Formatter(fmt_str, datefmt='%Y-%m-%d %H:%M:%S')
    console_handler.setFormatter(console_formatter)
    root_logger.addHandler(console_handler)

    if rest_endpoint:
        http_handler = HTTPLogHandler(rest_endpoint)
        root_logger.addHandler(http_handler)
    
    return root_logger
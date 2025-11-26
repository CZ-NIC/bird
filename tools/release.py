#!/usr/bin/python3

import logging
import sys

from Release import Release, ReleaseException

logging.basicConfig(format='%(levelname)# 8s | %(message)s', level=logging.INFO)
logger = logging.getLogger(__name__)

# Do the release preparation
try:
    Release().dispatch(sys.argv[1:])
except ReleaseException as e:
    logger.error(e, exc_info=True)
except Exception:
    logger.exception("Fatal error", exc_info=True)

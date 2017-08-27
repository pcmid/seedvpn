import logging

test = "qwer"
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s %(levelname)s %(message)s',
                    datefmt='%H:%M:%S %a, %d %b %Y ')

logging.debug('debug message %s ' %(test))
logging.info('info message')
logging.warning('warning message')
logging.error('error message')
logging.critical('critical message')

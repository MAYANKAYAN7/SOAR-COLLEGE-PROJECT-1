from dateutil import parser

def standardize_timestamp(timestamp):
    return parser.parse(timestamp).isoformat()
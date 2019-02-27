#!/usr/bin/env python
import preprocessing
mysql = {'host': 'localhost',
         'port': 'port'
         'user': 'user',
         'passwd': 'my secret password',}
preprocessing_queue = [preprocessing.scale_and_center,
                       preprocessing.dot_reduction,
                       preprocessing.connect_lines]
use_anonymous = True

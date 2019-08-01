import collections
import sqlite3 as lite
import logging
from datetime import datetime
from epastack.shared.task import Task
import epastack.shared.policies as policies
import os
import shutil


class Oracle:
    def __init__(self):
        # SET UP LOGGING
        logging.basicConfig(filename='oracle.log', level=logging.DEBUG)

    def get_kallsyms(self):
        '''
        This function copies the contents of the /proc/kallsym
        file into a text file, so that user does not have to manually
        add the kallsym in the oracle module.
        Work in Progress.
        :return:
        '''
        # save current directory
        oracle_direc = os.getcwd()

        # Change to /proc director and fetch kallsyms
        os.chdir(os.environ.get('HOME'))
        os.chdir('/proc')
        os.chmod()
        kallsysms = open('kallsyms', 'r')

        # Change back to oracle directory and create kall.text file
        os.chdir(oracle_direc)
        kall = open(os.path.join('epastack/oracle/', "kall.txt"), 'w+')

        shutil.copyfileobj(kallsysms, kall)

    def store_golden_values(self, task):
        '''
        Stores golden values in GOLDEN_VALUE table
        if the check returns the result as INIT
        :param task:
        :return:
        '''

        result_code = -1
        ts = datetime.now().time()

        try:
            connection = lite.connect('oracle.db')

            # Create GOLDEN_VALUES table
            cur = connection.cursor()
            sql = "CREATE TABLE IF NOT EXISTS GOLDEN_VALUES(ID INTEGER PRIMARY KEY, CHECK_ID TEXT, " \
                  "TASK_UUID TEXT, NODE_ID INTEGER, ADDRESS TEXT, COMMAND INTEGER, LEN INTEGER, " \
                  "COST INTEGER, TIMESTAMP TEXT, RESULT TEXT, HASH1 TEXT," \
                  "HASH2 TEXT, HASH3 TEXT, HASH4 TEXT, HASH5 TEXT, HASH6 TEXT, HASH7 TEXT, HASH8 TEXT)"
            cur.execute(sql)
            connection.commit()
            
            #Insert into GOLDEN_VALUES table
            sql = ("INSERT INTO GOLDEN_VALUES"
                  "('CHECK_ID', 'TASK_UUID','NODE_ID','ADDRESS','COMMAND', "
                  "'LEN', 'COST', 'TIMESTAMP', 'RESULT', 'HASH1', 'HASH2', 'HASH3', 'HASH4',"
                  "'HASH5','HASH6', 'HASH7', 'HASH8') "
                  "VALUES({},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{})").format(
                  str(task.check_id), str(task.task_uuid), task.node_id, str(task.address),
                  task.command, task.len, task.cost, str(ts), task.result, str(task.hash1),
                  str(task.hash2), str(task.hash3), str(task.hash4), str(task.hash5),
                  str(task.hash6), str(task.hash7), str(task.hash8))
            logging.debug("store_golden_values query: \n{}".format(sql))
            cur.execute(("INSERT INTO GOLDEN_VALUES"
                  "('CHECK_ID', 'TASK_UUID','NODE_ID','ADDRESS','COMMAND', "
                  "'LEN', 'COST', 'TIMESTAMP', 'RESULT', 'HASH1', 'HASH2', 'HASH3', 'HASH4',"
                  "'HASH5','HASH6', 'HASH7', 'HASH8') "
                  "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"),
                  (str(task.check_id), str(task.task_uuid), task.node_id, str(task.address),
                  task.command, task.len, task.cost, str(ts), task.result, str(task.hash1),
                  str(task.hash2), str(task.hash3), str(task.hash4), str(task.hash5),
                  str(task.hash6), str(task.hash7), str(task.hash8)))

            connection.commit()
            result_code = 1

        except lite.Error, e:
            logging.error("store_golden_values() SQLite Error: %s", e.args[0])
        finally:
            logging.info("result code from store_golden_values(): %s", result_code)
            connection.close()
            return result_code


    def log_results(self, task):
        '''
        Inserts into the RESULT_LOG table
        if the check returned the result as CHANGED/UNCHANGED
        :param task:
        :return:
        '''
        result_code = -1
        ts = datetime.now().time()


        try:
            connection = lite.connect('oracle.db')

            # Create RESULT_LOG TABLE
            cur = connection.cursor()
            sql = "CREATE TABLE IF NOT EXISTS RESULT_LOG" \
                  "(ID INTEGER PRIMARY KEY , CHECK_ID TEXT, TASK_UUID TEXT,NODE_ID INTEGER, ADDRESS TEXT, " \
                  "COMMAND INTEGER, LEN INTEGER, COST INTEGER,TIMESTAMP TEXT, RESULT INTEGER, HASH1 TEXT," \
                  "HASH2 TEXT, HASH3 TEXT, HASH4 TEXT, HASH5 TEXT, HASH6 TEXT, HASH7 TEXT, HASH8 TEXT)"
            cur.execute(sql)
            connection.commit()

            #Insert into RESULT_LOG table
            sql = "INSERT INTO RESULT_LOG" \
                  "('CHECK_ID', 'TASK_UUID','NODE_ID','ADDRESS','COMMAND','LEN', " \
                  "'COST','TIMESTAMP', 'RESULT', 'HASH1', 'HASH2', 'HASH3', 'HASH4'," \
                  "'HASH5','HASH6', 'HASH7', 'HASH8') VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?, ?)"
            cur.execute(sql,
                    (str(task.check_id), str(task.task_uuid),task.node_id, str(task.address), task.command, task.len, task.cost, str(ts), task.result, str(task.hash1), str(task.hash2), str(task.hash3), str(task.hash4),
                     str(task.hash5), str(task.hash6), str(task.hash7), str(task.hash8)))
            result_code = 1
            connection.commit()

        except lite.Error, e:
            logging.error("log_results() SQLite Error: %s", e.args[0])
            print("Error", e.args[0])

        finally:
            logging.info("result code from log_results(): %s", result_code)
            connection.close()
            return result_code


    def store_results(self, task):
        '''
        If the results provided are for the INIT operations
        store the golden values else store in the result_log table.
        When executed successfully, this function returns the result code as 1
        else return -1.
        :param task:
        :return:
        '''
        result_code = -1
        if isinstance(task, Task):
            # Determine whether the task result is to be logged in the result_log table or stored as initial golden values for the task
            if task.result: # Null Check
                if task.result == policies.INIT: # Store in the golden_values table
                    result_code = self.store_golden_values(task)
                elif task.result == policies.CHANGED or task.result == policies.UNCHANGED or task.result == policies.ERROR:
                    result_code = self.log_results(task)
            else:
                logging.info("store_results() : Result string empty. Data cannot be processed.")
                print("store_results() : Result string empty")
        else:
            logging.info("store_results(): Input parameter not of type Task" )
        return result_code


    def get_golden_values(self, task):
        '''
        This function retrieves golden values from GOLDEN_VALUE
        table based on the check_id, task_uuid, node_id,
        address and command that are passed as input parameters
        to the select query. Upon successful retrieval, it returns a list
        of golden values else an empty list.
        :param task:
        :return:
        '''
        if isinstance(task, Task):
            row = []
            try:
                connection = lite.connect('oracle.db')
                cur = connection.cursor()
                query = ('SELECT HASH1, HASH2, HASH3, HASH4, HASH5, HASH6, HASH7, HASH8 '
                        'FROM GOLDEN_VALUES WHERE NODE_ID = {} AND ADDRESS = {} '
                        'AND COMMAND = {} AND CHECK_ID = {} AND LEN = {}').format(
                            task.node_id, str(task.address), task.command, task.check_id, task.len
                        )
                logging.debug("get_golden_values query: \n{}".format(query))
                cur.execute(query)
                cur.execute(('SELECT HASH1, HASH2, HASH3, HASH4, HASH5, HASH6, HASH7, HASH8 '
                        'FROM GOLDEN_VALUES WHERE NODE_ID = ? AND ADDRESS = ? '
                        'AND COMMAND = ? AND CHECK_ID = ? AND LEN = ?'),
                        (task.node_id, str(task.address), task.command, task.check_id, task.len))
                row = cur.fetchone() # Ideally should return a single row

            except lite.Error, e:
                logging.error("get_golden_values() SQLite Error: %s", e.args[0])
                print("Error: ", e.args[0])

            finally:
                connection.close()
                logging.debug("get_golden_values() returning: %s", row)
                return row
        else:
            logging.info("get_golden_values(): Input parameter not of type Task")
            return []

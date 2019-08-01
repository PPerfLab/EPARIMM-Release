Oracle Module:
Currently, the oracle is responsible for the following functionalities:

    1. get_functions:
    - To use this function, add kall.txt file to oracle module. Please use absolute path for kall.txt when running this function inpendent of EPA-RIMM.
      Thus, if the file is not present in the oracle module, the code will break.
    - Input parameters required are:
        1. start_address
        2. end_address
        3. node_id (currently not being used)
    - The start and end address are decimal values obtained by converting the hexadcimal address to decimal.
        e.g the original start address is ffffffff81000000. In this case, the actual value to be passed to this function would be 18446744071578845184 which is the decimal form of the original start address.
        Similarly, end address is calculated.
    - The output of this function will be the list of kernel_symbols between the range of start and end address.
    - Usage: Oracle().get_functions(18446744071578845184,18446744071578849280, 0)
      Here, original start_address: ffffffff81000000
            original end_address : ffffffff81001000
 
    2. store_results:
    - Input parameters: task object
    - If the results provided are for the INIT operations
      store the golden values else store in the result_log table.
    - When executed successfully, this function returns the result code as 1
      else return -1.
 
    3. store_golden_values:
    - Input parameters: task object
    - Stores golden values in GOLDEN_VALUE table if the check returns the result as INIT
    
 
    4. log_results:
    - Input parameters: task object
    - Inserts into the RESULT_LOG table if the check returned the result as CHANGED/UNCHANGED
    
    
    5. get_golden_values:
    - Input parameters: task object
    - This function retrieves golden values from GOLDEN_VALUE table based on the check_id, task_uuid, node_id, address and command that are passed as input parameters
      to the select query. Upon successful retrieval, it returns a list of golden values else an empty list.
    
     
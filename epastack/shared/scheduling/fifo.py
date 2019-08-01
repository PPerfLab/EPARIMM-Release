from scheduler import Scheduler
from taskqueue import TaskQueue
import logging

class UnschedulableTaskException(Exception):
    def __init__(self, task):
        Exception.__init__(self, "Unschedulable Task encountered")
        self.task = task

class FifoQueue(TaskQueue):
    '''
        A priority-unaware fifo queue. For use with FifoScheduler.
    '''

    def __init__(self):
        self.queue = []

    def enqueue(self, task):
        self.queue.append(task)

    def pop(self):
        if self.queue:
            return self.queue.pop(0)
        return None
    def peek(self):
        if self.queue:
            return self.queue[0]
        return None

    def has_next(self):
        return self.queue

    def remove(self, task):
        self.queue.remove(task)

class FifoScheduler(Scheduler):
    '''
        A simple FIFO task scheduler - takes from the head of the queue of
        tasks until the bin is full.
    '''
    logger = logging.getLogger("FifoScheduler")

    def plan_bin(self, task_queue, bin_size):
        if not isinstance(task_queue, FifoQueue):
            raise RuntimeError(
                "FifoScheduler should only be used with FifoQueue")
        
        current_cost = 0
        bin = []
        while current_cost < bin_size and task_queue.has_next() and len(bin) < 13:
            next_task = task_queue.peek()
            t_cost = next_task.cost
            if t_cost is None:
                t_cost = bin_size     #TODO what should we estimate as the cost of a task with no known cost?
            if t_cost > bin_size:
                # Unschedulable task, remove it and alert the BEM.
                self.logger.error("Task cost is greater than bin size:")
                self.logger.error("Cost: {}\nBin Size: {}".format(str(t_cost), str(bin_size)))
                t = task_queue.pop()
                raise UnschedulableTaskException(t)
            current_cost += t_cost
            if current_cost > bin_size:
                # Bin is 'full'
                return bin
            bin.append(next_task) 
            task_queue.pop()
        return bin

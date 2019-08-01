import abc

class Scheduler(object):
    """
    This class is an abstract class for Schedulers -
    Actual scheduler implementations need to provide these methods,
    and should also provide an implementation of the TaskQueue base class.
    """

    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def plan_bin(self, task_queue, bin_size):
        """
        task_queue: a TaskQueue object.
        bin_budget: a numeric.
        This function accepts a task_queue (which can have whatever complexity
        is needed for the given scheduling algorith, including multiple
        internal queues, it just need to follow the interface), as well as
        a maximum bin budget.
        It must return a List of tasks (a bin) to be sent to the frontend.
        """
        pass

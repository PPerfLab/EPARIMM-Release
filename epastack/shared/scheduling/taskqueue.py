import abc

class TaskQueue(object):
    """
    This is an abstract class for TaskQueues -
    Actual implementations of this class should be used
    for various scheduling implementations. It represents a collection of tasks
    that are to be run against a Node. Despite its name, it does not have to be
    a singular queue - it may use whatever internal structure is preferred.
    """

    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def enqueue(self, task):
        """
        task: A Task Object
        This function is responsible for storing the provided task in the internal
        task queue structure.
        """
        pass

    @abc.abstractmethod
    def remove(self, task):
        """
        task: a Task Object
        This function will be called to remove tasks from the queue - either
        they have been scheduled, or becuase they have been cancelled.
        """
        pass
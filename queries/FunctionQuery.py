from binaryninja import *


class FunctionQuery:
    functions: List[Function] = None
    parameter_vars_min = None
    parameter_vars_max = None

    def __init__(self, functions: List[Function]):
        self.functions = functions

    def parameters(self, count: int):
        self.parameter_vars_min = count
        self.parameter_vars_max = count
        return self

    def parameters(self, min_count: int, max_count: int):
        self.parameter_vars_min = min_count
        self.parameter_vars_max = max_count
        return self

    def results(self) -> List[Function]:
        cloned: List = self.functions
        for func in self.functions:
            if self.parameter_vars_min is not None:
                parameters = List(func.parameter_vars)
                if len(parameters) > self.parameter_vars_max or len(parameters) < self.parameter_vars_min:
                    cloned.remove(func)
                    continue
        return cloned

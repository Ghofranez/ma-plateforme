from abc import ABC, abstractmethod

class UserRepositoryInterface(ABC):
    @abstractmethod
    def get_by_email(self, email: str): pass

    @abstractmethod
    def create(self, data: dict): pass

class AnalysisRepositoryInterface(ABC):
    @abstractmethod
    def create(self, data: dict): pass

    @abstractmethod
    def get_by_user(self, user_email: str): pass
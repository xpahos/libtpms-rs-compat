"""Registry of the five public suites, in execution order."""
from .golang import CanonicalGoTpm2, GoogleGoTpm
from .microsoft import MicrosoftTss
from .tpm2 import Tpm2Tools, Tpm2Tss

ADAPTERS = {adapter.name: adapter for adapter in
            (Tpm2Tss(), Tpm2Tools(), GoogleGoTpm(), CanonicalGoTpm2(), MicrosoftTss())}

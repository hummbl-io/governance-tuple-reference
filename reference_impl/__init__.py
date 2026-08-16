# MIT License
#
# Copyright (c) 2026 The Governance Tuple Authors
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

"""Reference implementation of the Governance Tuple primitives.

This package provides the anonymized, standalone implementation described in
the paper "The Governance Tuple: An Atomic Record for Auditable Agentic AI
Decision-Making". It is stdlib-only and MIT-licensed.
"""

from reference_impl.delegation_token import (
    DelegationCapabilityToken,
    DelegationTokenManager,
    TokenBinding,
    ResourceSelector,
    Caveat,
)
from reference_impl.delegation_context import (
    DelegationContext,
    DelegationContextManager,
    DelegationBudget,
    compute_dynamic_depth,
    DCTXStatus,
)
from reference_impl.governance_bus import (
    GovernanceBus,
    GovernanceEntry,
)
from reference_impl.adapter_receipt import (
    AdapterReceipt,
)
from reference_impl.basen_tuple import (
    BaseNTuple,
)

__all__ = [
    "DelegationCapabilityToken",
    "DelegationTokenManager",
    "TokenBinding",
    "ResourceSelector",
    "Caveat",
    "DelegationContext",
    "DelegationContextManager",
    "DelegationBudget",
    "compute_dynamic_depth",
    "DCTXStatus",
    "GovernanceBus",
    "GovernanceEntry",
    "AdapterReceipt",
    "BaseNTuple",
]

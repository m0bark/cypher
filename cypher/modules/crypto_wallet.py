"""Crypto wallet OSINT — public blockchain lookup for a BTC/ETH address.

Every on-chain transaction is public, so this reads the public ledger: for a
Bitcoin address it pulls balance and tx count (blockstream, no key), and for any
address it hands you explorer links. Public-ledger data only.
"""

from __future__ import annotations

from ..core.context import Context
from ..core.module import BaseModule, Finding, ModuleResult, Severity
from ..core.target import Target, TargetType


class CryptoWallet(BaseModule):
    name = "crypto_wallet"
    description = (
        "Public blockchain lookup for a BTC/ETH wallet address: chain, balance and "
        "tx count (Bitcoin, via blockstream), plus explorer links. Public ledger only."
    )
    applies_to = (TargetType.CRYPTO,)

    def run(self, target: Target, ctx: Context) -> ModuleResult:
        addr = target.value
        is_eth = addr.lower().startswith("0x")
        findings: list[Finding] = []

        if is_eth:
            findings.append(Finding("Chain", "Ethereum / EVM", Severity.INFO))
            links = {
                "Etherscan": f"https://etherscan.io/address/{addr}",
                "Blockchair": f"https://blockchair.com/ethereum/address/{addr}",
            }
        else:
            findings.append(Finding("Chain", "Bitcoin", Severity.INFO))
            links = {
                "Blockstream": f"https://blockstream.info/address/{addr}",
                "Blockchain.com": f"https://www.blockchain.com/explorer/addresses/btc/{addr}",
                "Blockchair": f"https://blockchair.com/bitcoin/address/{addr}",
            }
            try:
                data = ctx.http.get_json(f"https://blockstream.info/api/address/{addr}")
                cs = data.get("chain_stats", {})
                funded = cs.get("funded_txo_sum", 0)
                spent = cs.get("spent_txo_sum", 0)
                bal = (funded - spent) / 1e8
                findings.append(Finding("Balance", f"{bal:.8f} BTC", Severity.LOW))
                findings.append(Finding("Received (total)", f"{funded / 1e8:.8f} BTC", Severity.INFO))
                findings.append(Finding("Transactions", str(cs.get("tx_count", 0)), Severity.INFO))
            except Exception:
                pass

        for name, url in links.items():
            findings.append(Finding(name, url, Severity.INFO, {"url": url}))
        return ModuleResult(self.name, target.value, ok=True, findings=findings)

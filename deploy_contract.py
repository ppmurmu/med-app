# import json
# from solcx import compile_standard  # type: ignore # To compile the contract.sol file
# from web3 import Web3 # type: ignore
# import solcx # type: ignore

# w3 = Web3(Web3.HTTPProvider('http://127.0.0.1:7545'))  # Adjust if using a different provider

# # Check if Web3 is connected
# if not w3.is_connected():
#     raise Exception("Failed to connect to Ganache!")

# # Read contract from the Solidity file
# with open('MediChain.sol', 'r') as file:
#     contract_source_code = file.read()

# solcx.set_solc_version("0.8.0")
# compiled_sol = compile_standard({
#     "language": "Solidity",
#     "sources": {
#         "contract.sol": {
#             "content": contract_source_code
#         }
#     },
#     "settings": {
#         "outputSelection": {
#             "*": {
#                 "*": ["abi", "evm.bytecode"]
#             }
#         }
#     }
# })

# # Get ABI and Bytecode
# contract_abi = compiled_sol['contracts']['contract.sol']['MediChain']['abi']
# contract_bytecode = compiled_sol['contracts']['contract.sol']['MediChain']['evm']['bytecode']['object']

# # Set up account to deploy from
# deployer_address = '0x6cF49eb67D863546d773BBc8f0e91bee3e323ee0'  # Default Ganache account
# private_key = '0xc3bb4f3eca7a2e6932b59f9545e63b934a5d6320f5185835595b5859649b6601'  # Replace with your deployer's private key

# # Check if the deployer address has enough funds
# balance = w3.eth.get_balance(deployer_address)
# print(f"Deployer balance: {w3.from_wei(balance, 'ether')} ETH")

# # Create contract instance
# MediChain = w3.eth.contract(abi=contract_abi, bytecode=contract_bytecode)

# # Build transaction
# transaction = MediChain.constructor().build_transaction({
#     'from': deployer_address,
#     'gas': 6721975,  # Adjust if necessary
#     'gasPrice': w3.to_wei('20', 'gwei'),
#     'nonce': w3.eth.get_transaction_count(deployer_address),
# })

# # Sign the transaction
# signed_transaction = w3.eth.account.sign_transaction(transaction, private_key)

# # Send the transaction
# tx_hash = w3.eth.send_raw_transaction(signed_transaction.raw_transaction)

# # Wait for the receipt of the transaction (confirm contract deployment)
# tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

# # Print the contract address
# print(f"Contract deployed at address: {tx_receipt.contractAddress}")

# # Optionally save compiled contract (ABI and Bytecode) to a file
# compiled_contract_path = "compiled_contract.json"
# with open(compiled_contract_path, 'w') as compiled_file:
#     json.dump(compiled_sol, compiled_file, indent=4)

# print(f"Compiled contract saved to {compiled_contract_path}")


import json
from solcx import compile_standard  # type: ignore # To compile Solidity files
from web3 import Web3  # type: ignore
import solcx  # type: ignore
from dotenv import load_dotenv # type: ignore
import os

# Load environment variables from .env file
load_dotenv()
# Connect to hedera test net
WEB3_PROVIDER_URL = os.getenv('WEB3_PROVIDER_URL')
w3 = Web3(Web3.HTTPProvider(WEB3_PROVIDER_URL))
if not w3.is_connected():
    raise Exception("Failed to connect to Ganache!")

# Load both Solidity sources
with open('contracts/ClaimManager.sol', 'r', encoding='utf-8') as f:
    claim_manager_source = f.read()
with open('contracts/MediChain.sol', 'r', encoding='utf-8') as f:
    medichain_source = f.read()

# Set compiler version and enable optimizer

solcx.set_solc_version("0.8.12")
compiled_sol = compile_standard({
    "language": "Solidity",
    "sources": {
        "contracts/ClaimManager.sol": { "content": claim_manager_source },
        "contracts/MediChain.sol":    { "content": medichain_source    }
    },
    "settings": {
        "optimizer": { "enabled": True, "runs": 200 },
        "outputSelection": {
            "*": {
                "*": ["abi", "evm.bytecode", "evm.deployedBytecode"]
            }
        }
    }
})

# Extract ABI & Bytecode for MediChain
mcm = compiled_sol['contracts']['contracts/MediChain.sol']['MediChain']
contract_abi      = mcm['abi']
contract_bytecode = mcm['evm']['bytecode']['object']

# Deployer setup (adjust via env if desired)
deployer_address = w3.to_checksum_address('0x752054feb9b8d12e457e9cde267574b0bfaff7bf')
private_key      = '0x6f79a295f366c05f14f9dbc888f4919496f1ba5a21849f3fa02716c69d923c93'

# Check balance
balance = w3.eth.get_balance(deployer_address)
print(f"Deployer balance: {w3.from_wei(balance, 'ether')} ETH")

# Create and deploy contract
MediChain = w3.eth.contract(abi=contract_abi, bytecode=contract_bytecode)
transaction = MediChain.constructor().build_transaction({
    # 'from': deployer_address,
    # 'gas': 6721975,
    # 'gasPrice': w3.to_wei('20', 'gwei'),
    # 'nonce': w3.eth.get_transaction_count(deployer_address),
    'from': deployer_address,
    'chainId': int(os.getenv('CHAIN_ID', 296)),
    'gas': 2000000,
    'gasPrice': w3.eth.gas_price,
    'nonce': w3.eth.get_transaction_count(deployer_address),
})

signed_txn = w3.eth.account.sign_transaction(transaction, private_key)
tx_hash    = w3.eth.send_raw_transaction(signed_txn.raw_transaction)
tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
print(f"Contract deployed at address: {tx_receipt.contractAddress}")

# Save full compiled JSON
compiled_contract_path = "compiled_contract.json"
with open(compiled_contract_path, 'w') as cf:
    json.dump(compiled_sol, cf, indent=4)
print(f"Compiled contract saved to {compiled_contract_path}")

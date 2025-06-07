import asyncio
import sys

if sys.platform == "linux" or sys.platform == "linux2":
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        asyncio.set_event_loop(asyncio.new_event_loop())


from web3 import Web3
import requests
import json

import asyncio
import sys


# Connect to Ethereum node (Ganache)
web3 = Web3(Web3.HTTPProvider('http://localhost:7545'))

# Contract details
contract_address = "0xd9145CCE52D386f254917e481eB44e9943F39138"
abi = [
	{
		"anonymous": False,
		"inputs": [
			{
				"indexed": False,
				"internalType": "string",
				"name": "rule",
				"type": "string"
			},
			{
				"indexed": False,
				"internalType": "uint256",
				"name": "timestamp",
				"type": "uint256"
			}
		],
		"name": "PolicyAdded",
		"type": "event"
	},
	{
		"inputs": [
			{
				"internalType": "string",
				"name": "_rule",
				"type": "string"
			}
		],
		"name": "addPolicy",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "uint256",
				"name": "_index",
				"type": "uint256"
			}
		],
		"name": "getPolicy",
		"outputs": [
			{
				"internalType": "string",
				"name": "",
				"type": "string"
			},
			{
				"internalType": "uint256",
				"name": "",
				"type": "uint256"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [],
		"name": "getPolicyCount",
		"outputs": [
			{
				"internalType": "uint256",
				"name": "",
				"type": "uint256"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "uint256",
				"name": "",
				"type": "uint256"
			}
		],
		"name": "policies",
		"outputs": [
			{
				"internalType": "string",
				"name": "rule",
				"type": "string"
			},
			{
				"internalType": "uint256",
				"name": "timestamp",
				"type": "uint256"
			}
		],
		"stateMutability": "view",
		"type": "function"
	}
]  # Paste the ABI from your deployed contract

# Load the contract
contract = web3.eth.contract(address=contract_address, abi=abi)

# SDN Controller API URL
SDN_CONTROLLER_URL = "http://localhost:8080/policy"  # Replace with your SDN controller API

# Function to add a new policy to the blockchain
def add_policy_to_blockchain(rule):
    account = web3.eth.accounts[0]  # Use the first account in Ganache
    tx_hash = contract.functions.addPolicy(rule).transact({
        'from': account,
        'gas': 1000000
    })
    receipt = web3.eth.wait_for_transaction_receipt(tx_hash)
    return receipt

# Function to apply policy to SDN controller
def apply_policy_to_sdn(rule):
    payload = {"rule": rule}
    headers = {"Content-Type": "application/json"}
    response = requests.post(SDN_CONTROLLER_URL, data=json.dumps(payload), headers=headers)
    return response.status_code

# Function to fetch all policies from the blockchain
def fetch_policies():
    policy_count = contract.functions.getPolicyCount().call()
    policies = []
    for i in range(policy_count):
        rule, timestamp = contract.functions.getPolicy(i).call()
        policies.append({"rule": rule, "timestamp": timestamp})
    return policies

# Example usage
if __name__ == "__main__":
    # Add a new policy to the blockchain
    new_rule = "Allow traffic from 192.168.1.0/24"
    receipt = add_policy_to_blockchain(new_rule)
    print(f"Policy added to blockchain. Transaction receipt: {receipt}")

    # Apply the same policy to the SDN controller
    status_code = apply_policy_to_sdn(new_rule)
    print(f"Policy applied to SDN controller. Status code: {status_code}")

    # Fetch all policies from the blockchain
    policies = fetch_policies()
    print("All policies on the blockchain:")
    for policy in policies:
        print(f"Rule: {policy['rule']}, Timestamp: {policy['timestamp']}")

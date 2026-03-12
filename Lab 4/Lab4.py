from web3 import Web3


def main():
    # !/bin/env python3
    url = 'https://10.150.0.71:8545'
    # url = 'http://10.164.071:8545'
    web3 = Web3(Web3.HTTPProvider(url))  # Connect to a blockchain node

    # Account 30eth: 0xF5406927254d2dA7F7c28A61191e3Ff1f2400fe9
    # Account2-999: 0x2e2e3a61daC1A2056d9304F79C168cD16aAa88e9
    # Bob: 0xaB5AaD8284868B91Eb537d28aB1A159740D54890

    addr = Web3.toChecksumAddress('0x2e2e3a61daC1A2056d9304F79C168cD16aAa88e9')
    balance = web3.eth.get_balance(addr)  # Get the balance
    print(addr + ": " + str(Web3.fromWei(balance, 'ether')) + " ETH")


if __name__ == "__main__":
    main()

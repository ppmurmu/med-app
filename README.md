# Health Record Project

A blockchain-based healthcare records management system that securely stores and shares medical data between patients, doctors, and insurance providers.

## Overview

This project implements a decentralized application (dApp) that leverages blockchain technology to manage medical records with privacy, security, and patient consent at its core. Medical records are stored on IPFS (InterPlanetary File System) with access controls managed through smart contracts on the blockchain.

## Getting Started

### Prerequisites
- Python (Check your python version and accordingly use pip/pip3 or python/python3)

### Python packages
- Flask
- flaskWebGUI
- web3
- py-solc-x
- python-dotenv
- requests

### Installation

1. **Create and Activate a Virtual Environment:**
    ```bash
    python -m venv venv
    source venv/bin/activate  # Windows: venv\Scripts\activate
    ```

2. **Install Dependencies:**
    ```bash
    pip install -r requirements.txt
    ```
3. **Run the Application:**
    ```bash
    python app.py
    ```
    A desktop interface will launch, allowing you to interact with DApp.

### To deploy contract at new address

1. **Deploy the Smart Contract:**
    
    ```bash
    python deploy_contract.py
    ```
    Note the deployed contract address and update the `CONTRACT_ADDRESS` in `.env`.

2. **Set Up Environment Variables:**
    Create a `.env` file (or use the existing one) in the root directory and add:
    ```
    WEB3_PROVIDER_URL=hedera_api
    CONTRACT_ADDRESS=your_contract_address
    PINATA_API_KEY=your_pinata_api_key
    PINATA_SECRET_API_KEY=your_pinata_secret_api_key
    ```
    Update these values after you deploy the contract and set up Pinata.

3. **Update CONTRACT_ADDRESS in app.py:**
   ```
    At line 19 of app.py file, update CONTRACT_ADDRESS = w3.to_checksum_address('<YOUR_CONTRACT_ADDRESS>'):
    ```

## Features

### Patient Features
- Secure storage of medical records using IPFS
- Complete control over medical data access
- Grant and revoke doctor access permissions
- View comprehensive audit logs of all record access
- Request insurance claims with specific medical records
- User-friendly dashboard to manage all healthcare interactions

### Doctor Features
- Access patient records (with patient authorization)
- Upload and update patient medical records
- View patient history and medical documentation
- Transfer patients to other doctors when needed
- Approve insurance claims on behalf of patients

### Insurance Provider Features
- Process and settle claims with blockchain verification
- View authorized medical records for claim validation
- Maintain transparent history of processed claims

## Technical Architecture

The project consists of:

- **Smart Contracts**: Written in Solidity, managing data access permissions, user roles, and system logic
- **Web Application**: Flask-based frontend for user interaction
- **Blockchain Integration**: Web3.py for interaction with the blockchain
- **File Storage**: IPFS via Pinata for decentralized storage of medical records

## Security Features

- Private key authentication for secure access
- Role-based access control (patient, doctor, insurer)
- Comprehensive audit trails for all record access
- Patient-controlled data sharing
- Immutable record of all healthcare interactions

## Tech Stack

- **Backend**: Python, Flask
- **Frontend**: HTML, CSS, Bootstrap
- **Blockchain**: Hedera (EVM compatible)
- **Smart Contracts**: Solidity
- **Storage**: IPFS (via Pinata)
- **Blockchain Interface**: Web3.py



## Future Enhancements

- Mobile application support
- Integration with existing electronic health record (EHR) systems
- Multi-factor authentication
- Enhanced analytics for healthcare providers
- Support for additional blockchain networks

## License

This project is licensed under the MIT License - see the LICENSE file for details.